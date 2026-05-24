"""Container and Kubernetes security knowledge base.

Deep knowledge about container security:
1. Docker security
2. Kubernetes security
3. Container image security
4. Runtime protection
5. Service mesh security
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


CONTAINER_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ctn-001", "name": "Docker Security",
        "category": "docker", "severity": "high",
        "desc": "Docker security assessment.",
        "detection": (
            "DOCKER SECURITY:\n"
            "CONFIGURATION:\n"
            "  # Docker daemon audit\n"
            "  docker info\n"
            "  docker version\n"
            "  # CIS Docker Benchmark\n"
            "  docker-bench-security\n"
            "  # Check for privileged containers\n"
            "  docker ps --format '{{.Names}} {{.Status}}'\n"
            "  docker inspect --format='{{.HostConfig.Privileged}}' <container>\n"
            "VULNERABILITIES:\n"
            "  - Docker socket exposure (/var/run/docker.sock)\n"
            "  - Privileged mode (--privileged)\n"
            "  - Host namespace sharing (--pid=host)\n"
            "  - Capability abuse (--cap-add=ALL)\n"
            "  - Sensitive volume mounts (-v /:/host)\n"
            "  - Default bridge network (no isolation)\n"
            "  - Root user inside container\n"
            "DOCKERFILE:\n"
            "  - Running as root (no USER directive)\n"
            "  - Using :latest tag\n"
            "  - Exposing unnecessary ports\n"
            "  - Storing secrets in layers\n"
            "  - Large attack surface (ubuntu vs alpine)\n"
            "  - Missing health checks\n"
            "TOOLS:\n"
            "  docker-bench-security, hadolint, dockle, dive"
        ),
        "tools": ["docker-bench", "hadolint", "dockle"],
    },
    {
        "id": "ctn-002", "name": "Kubernetes Security",
        "category": "kubernetes", "severity": "critical",
        "desc": "Kubernetes cluster security.",
        "detection": (
            "KUBERNETES SECURITY:\n"
            "CLUSTER ACCESS:\n"
            "  # API server exposure\n"
            "  curl -k https://<api-server>:6443/\n"
            "  # Anonymous auth check\n"
            "  curl -k https://<api-server>:6443/api/v1/namespaces\n"
            "  # Kubelet API (10250)\n"
            "  curl -k https://<node>:10250/pods/\n"
            "  # etcd (2379)\n"
            "  etcdctl get / --prefix --keys-only\n"
            "RBAC:\n"
            "  # Enumerate permissions\n"
            "  kubectl auth can-i --list\n"
            "  kubectl auth can-i create pods\n"
            "  # Overprivileged service accounts\n"
            "  # cluster-admin binding\n"
            "  kubectl get clusterrolebindings -o json\n"
            "POD SECURITY:\n"
            "  - PodSecurityAdmission (PSA)\n"
            "  - Privileged pods\n"
            "  - hostPath volumes\n"
            "  - hostNetwork/hostPID/hostIPC\n"
            "  - Service account token automount\n"
            "  - SecurityContext (runAsNonRoot, capabilities)\n"
            "SECRETS:\n"
            "  # Secrets are base64, not encrypted!\n"
            "  kubectl get secrets -A\n"
            "  kubectl get secret <name> -o jsonpath='{.data}'\n"
            "  # Use: external-secrets, vault, sealed-secrets\n"
            "TOOLS:\n"
            "  kube-bench, kubeaudit, kube-hunter, kubesec"
        ),
        "tools": ["kube-bench", "kube-hunter"],
    },
    {
        "id": "ctn-003", "name": "Container Image Security",
        "category": "images", "severity": "high",
        "desc": "Container image security scanning.",
        "detection": (
            "CONTAINER IMAGE SECURITY:\n"
            "SCANNING:\n"
            "  # Trivy (vulnerability + misconfiguration)\n"
            "  trivy image nginx:latest\n"
            "  trivy image --severity HIGH,CRITICAL myapp:v1\n"
            "  # Grype\n"
            "  grype nginx:latest\n"
            "  # Snyk Container\n"
            "  snyk container test nginx:latest\n"
            "ANALYSIS:\n"
            "  # Layer analysis\n"
            "  dive nginx:latest  # Interactive layer explorer\n"
            "  # History\n"
            "  docker history nginx:latest\n"
            "  # Extract filesystem\n"
            "  docker save nginx:latest | tar xf -\n"
            "SUPPLY CHAIN:\n"
            "  - Verify image signatures (cosign)\n"
            "  - Content trust (Docker Content Trust)\n"
            "  - Admission controllers (OPA/Gatekeeper)\n"
            "  - Allowed registries only\n"
            "  - SBOM generation (syft)\n"
            "HARDENING:\n"
            "  - Minimal base images (distroless, alpine)\n"
            "  - Multi-stage builds\n"
            "  - Non-root user\n"
            "  - Read-only filesystem\n"
            "  - No package managers in prod image\n"
            "  - Pin versions (not :latest)\n"
            "TOOLS:\n"
            "  Trivy, Grype, Snyk, Cosign, Syft, Dive"
        ),
        "tools": ["trivy", "grype", "dive"],
    },
    {
        "id": "ctn-004", "name": "Runtime Protection",
        "category": "runtime", "severity": "high",
        "desc": "Container runtime security.",
        "detection": (
            "RUNTIME PROTECTION:\n"
            "MONITORING:\n"
            "  # Falco (runtime threat detection)\n"
            "  # Syscall monitoring\n"
            "  # Default rules: shell in container, sensitive file access\n"
            "  # Custom rules for your workload\n"
            "SECCOMP:\n"
            "  - Limit syscalls available to container\n"
            "  - Default Docker profile (blocks 44 syscalls)\n"
            "  - Custom profiles per container\n"
            "  - seccomp: unconfined (dangerous!)\n"
            "APPARMOR/SELINUX:\n"
            "  - AppArmor profiles for containers\n"
            "  - SELinux labels (enforce separation)\n"
            "  - Default Docker AppArmor profile\n"
            "  - Custom profiles for least privilege\n"
            "READ-ONLY:\n"
            "  - --read-only flag\n"
            "  - tmpfs for writeable directories\n"
            "  - Prevent filesystem modification\n"
            "  - Detect anomalous writes\n"
            "NETWORK POLICIES:\n"
            "  - Default deny all traffic\n"
            "  - Allow only necessary communication\n"
            "  - NetworkPolicy objects in K8s\n"
            "  - Cilium, Calico for enforcement\n"
            "TOOLS:\n"
            "  Falco, Sysdig, Tracee, Tetragon"
        ),
        "tools": ["falco", "tracee"],
    },
    {
        "id": "ctn-005", "name": "Service Mesh Security",
        "category": "mesh", "severity": "medium",
        "desc": "Service mesh security assessment.",
        "detection": (
            "SERVICE MESH SECURITY:\n"
            "ISTIO:\n"
            "  - mTLS between services\n"
            "  - PeerAuthentication policy\n"
            "  - AuthorizationPolicy\n"
            "  - RequestAuthentication (JWT)\n"
            "  # Check mTLS status\n"
            "  istioctl analyze\n"
            "  istioctl proxy-status\n"
            "ATTACKS:\n"
            "  - mTLS not enforced (PERMISSIVE mode)\n"
            "  - Sidecar injection bypass\n"
            "  - Control plane compromise\n"
            "  - Envoy proxy vulnerabilities\n"
            "  - Gateway misconfiguration\n"
            "LINKERD:\n"
            "  - Automatic mTLS\n"
            "  - Policy engine\n"
            "  - Viz dashboard exposure\n"
            "  # Health check\n"
            "  linkerd check\n"
            "ASSESSMENT:\n"
            "  - Verify mTLS enforcement\n"
            "  - Check AuthorizationPolicies\n"
            "  - Test service-to-service access\n"
            "  - Audit gateway configurations\n"
            "  - Review JWT validation\n"
            "  - Check for permissive policies\n"
            "TOOLS:\n"
            "  istioctl, linkerd, meshery"
        ),
        "tools": ["istioctl"],
    },
]


class ContainerSecurityKB:
    """Container security knowledge base.

    Provides container/K8s patterns injected into agent prompts.
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
                severity=data.get("severity", "high"),
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
        lines = ["## Container & K8s Security\n"]
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
