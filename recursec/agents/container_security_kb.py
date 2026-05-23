"""Container security knowledge base.

Deep knowledge about container and Docker security:
1. Docker image security
2. Container runtime security
3. Container escape techniques
4. Supply chain security
5. Container registry security
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ContainerVulnPattern:
    """A container vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:12],
        }


CONTAINER_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cnt-001", "name": "Docker Image Security",
        "category": "image", "severity": "high",
        "desc": "Docker image vulnerability analysis.",
        "testing": (
            "DOCKER IMAGE SECURITY:\n"
            "1. IMAGE SCANNING:\n"
            "   - Vulnerability scan:\n"
            "     trivy image {image}:{tag}\n"
            "     grype {image}:{tag}\n"
            "   - Secret scanning in layers:\n"
            "     docker history {image} --no-trunc\n"
            "     dive {image}:{tag} (interactive layer browser)\n"
            "   - Check for hardcoded credentials\n"
            "2. DOCKERFILE ANALYSIS:\n"
            "   - Base image: Use specific tags, not 'latest'\n"
            "   - USER directive: Don't run as root\n"
            "   - COPY vs ADD: ADD can fetch URLs, prefer COPY\n"
            "   - Multi-stage builds: Don't include build tools in final image\n"
            "   - .dockerignore: Exclude .git, .env, secrets\n"
            "   - hadolint Dockerfile (Dockerfile linter)\n"
            "3. BASE IMAGE RISKS:\n"
            "   - OS-level CVEs in base image\n"
            "   - Unnecessary packages (apt-get install without cleanup)\n"
            "   - Distroless or Alpine vs full Ubuntu/Debian\n"
            "   - Image provenance and signing (cosign/Notary)\n"
            "4. LAYER INSPECTION:\n"
            "   - Extract filesystem layers:\n"
            "     docker save {image} | tar xf -\n"
            "   - Inspect each layer for:\n"
            "     * Credentials, API keys, passwords\n"
            "     * Private keys, certificates\n"
            "     * Configuration files with secrets\n"
            "   - Tools: dive, container-diff\n"
            "5. SBOM GENERATION:\n"
            "   - syft {image}:{tag} (generate SBOM)\n"
            "   - Verify against known vuln databases"
        ),
        "tools": ["trivy", "grype", "dive", "hadolint", "syft"],
    },
    {
        "id": "cnt-002", "name": "Container Runtime Security",
        "category": "runtime", "severity": "critical",
        "desc": "Container runtime security assessment.",
        "testing": (
            "CONTAINER RUNTIME SECURITY:\n"
            "1. DOCKER DAEMON:\n"
            "   - Docker socket exposure:\n"
            "     ls -la /var/run/docker.sock\n"
            "     Check if mounted inside containers (→ full host control)\n"
            "   - Remote API:\n"
            "     curl http://{host}:2375/version (unauthenticated Docker API)\n"
            "     curl http://{host}:2376/version (TLS, check cert validation)\n"
            "   - Docker socket in TCP without TLS → critical\n"
            "2. CONTAINER CONFIGURATION:\n"
            "   - Privileged mode:\n"
            "     docker inspect {container} | jq '.[].HostConfig.Privileged'\n"
            "     Privileged = full host kernel access\n"
            "   - Capabilities:\n"
            "     docker inspect {container} | jq '.[].HostConfig.CapAdd'\n"
            "     Dangerous: SYS_ADMIN, SYS_PTRACE, NET_ADMIN, DAC_READ_SEARCH\n"
            "   - Seccomp profile:\n"
            "     docker inspect {container} | jq '.[].HostConfig.SecurityOpt'\n"
            "     'unconfined' = no syscall filtering\n"
            "   - AppArmor/SELinux profile\n"
            "3. NAMESPACE ISOLATION:\n"
            "   - PID namespace: --pid=host shares host process tree\n"
            "   - Network namespace: --net=host shares host network\n"
            "   - IPC namespace: --ipc=host shares host IPC\n"
            "   - UTS namespace: --uts=host shares hostname\n"
            "4. RESOURCE LIMITS:\n"
            "   - CPU limits: --cpus, --cpu-shares\n"
            "   - Memory limits: --memory, --memory-swap\n"
            "   - PID limits: --pids-limit\n"
            "   - No limits = DoS potential\n"
            "5. DOCKER BENCH:\n"
            "   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\\n"
            "     docker/docker-bench-security"
        ),
        "tools": ["docker-bench-security", "amicontained", "deepce"],
    },
    {
        "id": "cnt-003", "name": "Container Escape Techniques",
        "category": "escape", "severity": "critical",
        "desc": "Techniques to escape container isolation.",
        "testing": (
            "CONTAINER ESCAPE TECHNIQUES:\n"
            "1. PRIVILEGED MODE ESCAPE:\n"
            "   - If container is privileged:\n"
            "     mount /dev/sda1 /mnt  (mount host disk)\n"
            "     chroot /mnt\n"
            "     nsenter -t 1 -m -u -n -i bash (enter host namespaces)\n"
            "2. DOCKER SOCKET ESCAPE:\n"
            "   - If /var/run/docker.sock is mounted:\n"
            "     docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host\n"
            "     → Full host access\n"
            "3. CGROUP ESCAPE (CVE-2022-0492):\n"
            "   - release_agent exploit:\n"
            "     mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp\n"
            "     echo 1 > /tmp/cgrp/notify_on_release\n"
            "     Write payload to release_agent\n"
            "4. CAPABILITY-BASED ESCAPE:\n"
            "   - SYS_ADMIN: mount overlayfs, abuse cgroups\n"
            "   - SYS_PTRACE: ptrace host processes\n"
            "   - DAC_READ_SEARCH: Read any file on host\n"
            "   - NET_ADMIN: Manipulate host networking\n"
            "5. KERNEL EXPLOIT:\n"
            "   - Dirty Pipe (CVE-2022-0847): Overwrite read-only files\n"
            "   - Dirty COW (CVE-2016-5195): Copy-on-write race\n"
            "   - Container runtime CVEs (runc, containerd)\n"
            "6. SIDE CHANNELS:\n"
            "   - /proc/self/environ: Read environment variables\n"
            "   - /proc/1/root: Access host root filesystem (PID namespace shared)\n"
            "   - Cloud metadata: curl 169.254.169.254 from container\n"
            "7. DETECTION:\n"
            "   - Check if in container:\n"
            "     cat /proc/1/cgroup (look for docker/kubepods)\n"
            "     ls /.dockerenv\n"
            "   - deepce: Docker container escape tool\n"
            "   - amicontained: Container introspection"
        ),
        "tools": ["deepce", "amicontained", "CDK"],
    },
    {
        "id": "cnt-004", "name": "Container Supply Chain",
        "category": "supply_chain", "severity": "high",
        "desc": "Container supply chain security.",
        "testing": (
            "CONTAINER SUPPLY CHAIN SECURITY:\n"
            "1. REGISTRY SECURITY:\n"
            "   - Private registry enumeration:\n"
            "     curl https://{registry}/v2/_catalog\n"
            "     curl https://{registry}/v2/{image}/tags/list\n"
            "   - Anonymous pull access\n"
            "   - Image deletion without auth\n"
            "   - Content trust (DCT/Notary) enforcement\n"
            "2. IMAGE PROVENANCE:\n"
            "   - Verify image signatures:\n"
            "     cosign verify {image}\n"
            "   - SLSA provenance attestation\n"
            "   - Build reproducibility\n"
            "   - Sigstore/Rekor transparency log\n"
            "3. DEPENDENCY ATTACKS:\n"
            "   - Typosquatting: Similar image names on Docker Hub\n"
            "   - Dependency confusion: Private vs public registry\n"
            "   - Compromised base images\n"
            "   - Malicious packages in build dependencies\n"
            "4. CI/CD PIPELINE:\n"
            "   - Build secrets in Docker images\n"
            "   - Buildkit secrets vs ARG/ENV\n"
            "   - Pipeline injection (Dockerfile/compose injection)\n"
            "   - Admission controllers: OPA Gatekeeper, Kyverno\n"
            "5. RUNTIME VERIFICATION:\n"
            "   - Image policy enforcement\n"
            "   - Allowed registries whitelist\n"
            "   - Tag immutability\n"
            "   - Vulnerability gate (block deploy if critical CVEs)"
        ),
        "tools": ["cosign", "syft", "grype", "OPA Gatekeeper", "Kyverno"],
    },
]


class ContainerSecurityKB:
    """Container security knowledge base.

    Provides container security testing methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ContainerVulnPattern] = {}
        self._log = logger.bind(component="container_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load container vulnerability patterns."""
        for data in CONTAINER_VULN_PATTERNS:
            pattern = ContainerVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[ContainerVulnPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def build_container_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build container security prompt."""
        lines = ["## Container Security Testing\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            lines.append(pattern.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
