"""Container and Docker security deep-dive knowledge base.

Deep knowledge about container security:
1. Docker daemon and socket attacks
2. Container escape techniques
3. Image security and supply chain
4. Runtime security and monitoring
5. Orchestration security (K8s, Swarm)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ContainerPattern:
    """A container security pattern."""
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


CONTAINER_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cnt-001", "name": "Docker Daemon Attacks",
        "category": "daemon", "severity": "critical",
        "desc": "Docker daemon and socket attacks.",
        "detection": (
            "DOCKER DAEMON ATTACKS:\n"
            "SOCKET EXPOSURE:\n"
            "  # Check if Docker socket is mounted\n"
            "  ls -la /var/run/docker.sock\n"
            "  # If accessible → full host compromise\n"
            "  docker -H unix:///var/run/docker.sock ps\n"
            "  # Mount host filesystem\n"
            "  docker run -v /:/host --rm -it alpine chroot /host\n"
            "REMOTE API:\n"
            "  # Exposed Docker API (port 2375/2376)\n"
            "  curl http://TARGET:2375/version\n"
            "  curl http://TARGET:2375/containers/json\n"
            "  # Create privileged container remotely\n"
            "  docker -H tcp://TARGET:2375 run -v /:/mnt --rm -it alpine\n"
            "DAEMON CONFIG:\n"
            "  - --privileged flag (disable security)\n"
            "  - --net=host (host networking)\n"
            "  - --pid=host (host PID namespace)\n"
            "  - --ipc=host (host IPC)\n"
            "  - --userns-host (no user namespace)\n"
            "REGISTRIES:\n"
            "  - Unauthenticated registry\n"
            "  curl http://TARGET:5000/v2/_catalog\n"
            "  - Image tag overwrite\n"
            "  - Credential harvesting (~/.docker/config.json)\n"
            "TOOLS:\n"
            "  Docker Bench, deepce, CDK"
        ),
        "tools": ["deepce"],
    },
    {
        "id": "cnt-002", "name": "Container Escape",
        "category": "escape", "severity": "critical",
        "desc": "Container escape techniques.",
        "detection": (
            "CONTAINER ESCAPE:\n"
            "DETECTION:\n"
            "  # Am I in a container?\n"
            "  cat /proc/1/cgroup | grep docker\n"
            "  ls /.dockerenv\n"
            "  cat /proc/self/mountinfo | grep overlay\n"
            "SOCKET MOUNT:\n"
            "  # Docker socket mounted inside container\n"
            "  ls /var/run/docker.sock\n"
            "  # Escape: create privileged container\n"
            "  docker run -v /:/host --privileged --rm -it alpine\n"
            "PRIVILEGED:\n"
            "  # Privileged container → full host\n"
            "  # Mount host disk\n"
            "  fdisk -l  # find host disk\n"
            "  mkdir /mnt/host\n"
            "  mount /dev/sda1 /mnt/host\n"
            "  # Or via cgroup release_agent\n"
            "  # (CVE-2022-0492)\n"
            "CAPABILITIES:\n"
            "  # Check capabilities\n"
            "  capsh --print\n"
            "  # CAP_SYS_ADMIN → mount, cgroups\n"
            "  # CAP_SYS_PTRACE → process injection\n"
            "  # CAP_NET_ADMIN → network manipulation\n"
            "  # CAP_DAC_OVERRIDE → file access\n"
            "KERNEL EXPLOITS:\n"
            "  - CVE-2019-5736 (runc overwrite)\n"
            "  - CVE-2020-15257 (containerd shim)\n"
            "  - CVE-2022-0185 (file_system_context)\n"
            "  - CVE-2024-21626 (runc WORKDIR)\n"
            "  - Dirty Pipe (CVE-2022-0847)\n"
            "TOOLS:\n"
            "  CDK, deepce, PEIRATES, amicontained"
        ),
        "tools": ["deepce"],
    },
    {
        "id": "cnt-003", "name": "Image Security",
        "category": "image", "severity": "high",
        "desc": "Container image security.",
        "detection": (
            "IMAGE SECURITY:\n"
            "SCANNING:\n"
            "  # Trivy (comprehensive)\n"
            "  trivy image TARGET_IMAGE\n"
            "  trivy image --severity CRITICAL,HIGH TARGET_IMAGE\n"
            "  # Grype\n"
            "  grype TARGET_IMAGE\n"
            "  # Snyk Container\n"
            "  snyk container test TARGET_IMAGE\n"
            "ANALYSIS:\n"
            "  # Dive (inspect layers)\n"
            "  dive TARGET_IMAGE\n"
            "  # Export and inspect\n"
            "  docker save IMAGE | tar -xf -\n"
            "  # Check each layer for secrets\n"
            "  # Check for SUID binaries\n"
            "  find / -perm -4000 -type f 2>/dev/null\n"
            "SUPPLY CHAIN:\n"
            "  - Base image vulnerabilities\n"
            "  - Multi-stage build leakage\n"
            "  - Build secret exposure\n"
            "  - Unsigned images\n"
            "  # cosign verify IMAGE\n"
            "  - Missing SBOM\n"
            "  # syft packages IMAGE\n"
            "BEST PRACTICES:\n"
            "  - Minimal base (distroless, scratch, Alpine)\n"
            "  - No root user in container\n"
            "  - Read-only filesystem\n"
            "  - No secrets in layers\n"
            "  - Pin image digests (not tags)\n"
            "TOOLS:\n"
            "  Trivy, Grype, Dive, cosign, syft"
        ),
        "tools": ["trivy"],
    },
    {
        "id": "cnt-004", "name": "Runtime Security",
        "category": "runtime", "severity": "high",
        "desc": "Container runtime security.",
        "detection": (
            "RUNTIME SECURITY:\n"
            "SYSCALL FILTERING:\n"
            "  - seccomp profiles\n"
            "  - Default seccomp blocks ~44 syscalls\n"
            "  - Custom profiles per container\n"
            "  # Check: docker inspect | grep SecurityOpt\n"
            "MAC:\n"
            "  - AppArmor profiles\n"
            "  - SELinux contexts\n"
            "  # Check: aa-status\n"
            "  # Check: getenforce\n"
            "RESOURCE LIMITS:\n"
            "  - CPU limits (--cpus)\n"
            "  - Memory limits (--memory)\n"
            "  - PID limits (--pids-limit)\n"
            "  - File descriptor limits\n"
            "  - No limits = DoS risk\n"
            "NETWORKING:\n"
            "  - Container-to-container traffic\n"
            "  - Network segmentation\n"
            "  - Exposed ports mapping\n"
            "  - DNS resolution abuse\n"
            "  - iptables/nftables rules\n"
            "MONITORING:\n"
            "  - Falco (runtime threat detection)\n"
            "  - Sysdig (container-aware)\n"
            "  - auditd integration\n"
            "  - File integrity monitoring\n"
            "  - Process monitoring\n"
            "TOOLS:\n"
            "  Falco, Sysdig, Docker Bench, auditd"
        ),
        "tools": ["falco"],
    },
    {
        "id": "cnt-005", "name": "Orchestration Security",
        "category": "orchestration", "severity": "critical",
        "desc": "Kubernetes and Swarm security.",
        "detection": (
            "ORCHESTRATION SECURITY:\n"
            "KUBERNETES:\n"
            "  API SERVER:\n"
            "    # Unauthenticated access\n"
            "    curl -k https://TARGET:6443/api\n"
            "    curl -k https://TARGET:6443/api/v1/pods\n"
            "    # kubelet API (10250)\n"
            "    curl -k https://TARGET:10250/pods\n"
            "    curl -k https://TARGET:10250/run/NAMESPACE/POD/CONTAINER\n"
            "  RBAC:\n"
            "    - Overly permissive ClusterRoles\n"
            "    - Default service account tokens\n"
            "    - Token mounted in every pod\n"
            "    kubectl auth can-i --list\n"
            "  SECRETS:\n"
            "    - Base64-encoded (not encrypted)\n"
            "    - etcd unencrypted at rest\n"
            "    - Secret access via RBAC\n"
            "    kubectl get secrets -A\n"
            "  NETWORK POLICY:\n"
            "    - Default: all pods can talk\n"
            "    - Missing network policies\n"
            "    - Namespace boundaries\n"
            "  POD SECURITY:\n"
            "    - Privileged pods\n"
            "    - hostPath mounts\n"
            "    - hostNetwork/hostPID\n"
            "    - Capabilities\n"
            "    - PSA (Pod Security Admission)\n"
            "DOCKER SWARM:\n"
            "  - Manager node compromise\n"
            "  - Secret management\n"
            "  - Network overlay security\n"
            "  - Service mesh configuration\n"
            "TOOLS:\n"
            "  kube-hunter, kube-bench, kubeaudit, PEIRATES"
        ),
        "tools": ["kube-hunter"],
    },
]


class ContainerDeepKB:
    """Container and Docker security deep-dive KB.

    Provides container security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ContainerPattern] = {}
        self._log = logger.bind(component="container_deep_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load container patterns."""
        for data in CONTAINER_PATTERNS:
            pattern = ContainerPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[ContainerPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_container_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build container security prompt."""
        lines = ["## Container Security\n"]
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
