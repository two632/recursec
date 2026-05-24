"""Container and Kubernetes security knowledge base.

Attack patterns for container/K8s environments:
1. Container Escape — kernel exploits, privileged containers, mount abuse
2. Kubernetes API Attacks — RBAC abuse, service account token theft
3. Image Supply Chain — malicious base images, layer poisoning
4. Network Policy Bypass — pod-to-pod, service mesh misconfiguration
5. Secrets Management — etcd exposure, env var leaks, configmap abuse
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContainerAttackType(str, Enum):
    CONTAINER_ESCAPE = "container_escape"
    K8S_API = "k8s_api"
    IMAGE_SUPPLY_CHAIN = "image_supply_chain"
    NETWORK_POLICY = "network_policy"
    SECRETS_MGMT = "secrets_mgmt"


@dataclass
class ContainerPattern:
    """A container/K8s attack pattern."""
    name: str = ""
    attack_type: ContainerAttackType = ContainerAttackType.CONTAINER_ESCAPE
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
        }


CONTAINER_PATTERNS: list[ContainerPattern] = [
    ContainerPattern(
        name="Container Escape",
        attack_type=ContainerAttackType.CONTAINER_ESCAPE,
        description=(
            "Breaking out of container isolation to access the host: "
            "kernel exploit (CVE-2022-0185, CVE-2024-21626), privileged "
            "container abuse, Docker socket mount, cgroup escape."
        ),
        detection_strategies=[
            "Check if container runs as privileged (--privileged)",
            "Check for Docker socket mounted (/var/run/docker.sock)",
            "Verify seccomp profile is applied (not unconfined)",
            "Check for host PID/network/IPC namespace sharing",
            "Identify writable host mount points (/host, /proc, /sys)",
            "Check kernel version for known escape CVEs",
            "Verify AppArmor/SELinux profile is enforced",
            "Check for SYS_ADMIN and other dangerous capabilities",
        ],
        indicators=[
            "Container running with --privileged flag",
            "Docker socket accessible inside container",
            "seccomp=unconfined in container config",
            "hostPID: true or hostNetwork: true in pod spec",
            "Writable /proc/sys or /sys/fs/cgroup mounts",
            "CAP_SYS_ADMIN or CAP_SYS_PTRACE granted",
        ],
        tools=["trivy", "falco", "kube-bench", "amicontained",
               "deepce", "CDK"],
        commands=[
            "cat /proc/1/cgroup | grep docker",
            "ls -la /var/run/docker.sock",
            "cat /proc/self/status | grep -i cap",
            "amicontained",
            "deepce.sh --exploit",
            "mount | grep -E 'proc|sys|cgroup'",
        ],
        mitre_ids=["T1611"],
        severity="critical",
    ),
    ContainerPattern(
        name="Kubernetes API Attacks",
        attack_type=ContainerAttackType.K8S_API,
        description=(
            "Attacking Kubernetes API server: RBAC privilege escalation, "
            "service account token abuse, API server misconfiguration, "
            "admission controller bypass, etcd direct access."
        ),
        detection_strategies=[
            "Check for overly permissive RBAC (cluster-admin bindings)",
            "Test service account token permissions from pods",
            "Check if API server is publicly accessible",
            "Verify anonymous authentication is disabled",
            "Check for node/proxy RBAC escalation paths",
            "Test admission controller webhook bypass",
            "Check etcd encryption and access controls",
            "Verify audit logging is enabled on API server",
        ],
        indicators=[
            "Service account with cluster-admin role",
            "API server accessible without authentication",
            "Anonymous auth enabled on API server",
            "etcd accessible without mTLS",
            "Admission webhooks in failOpen mode",
            "Excessive RBAC permissions (list/get/watch all)",
        ],
        tools=["kubectl", "kubeaudit", "kube-bench", "kube-hunter",
               "rbac-police", "peirates"],
        commands=[
            "kubectl auth can-i --list",
            "kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[].name==\"system:anonymous\")'",
            "kubectl get secrets --all-namespaces",
            "kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.serviceAccountName}{\"\\n\"}{end}'",
            "peirates",
            "kube-bench run --targets master",
        ],
        mitre_ids=["T1078.004", "T1552"],
        severity="critical",
    ),
    ContainerPattern(
        name="Image Supply Chain",
        attack_type=ContainerAttackType.IMAGE_SUPPLY_CHAIN,
        description=(
            "Attacking container image supply chain: malicious base images, "
            "layer poisoning, registry credential theft, image tag "
            "mutability, and unsigned image deployment."
        ),
        detection_strategies=[
            "Scan images for known CVEs before deployment",
            "Verify images are signed (cosign, notary)",
            "Check if images use mutable tags (:latest)",
            "Verify base images are from trusted registries",
            "Analyze image layers for suspicious additions",
            "Check for secrets embedded in image layers",
            "Monitor registry for unauthorized image pushes",
            "Verify image pull policy prevents cached stale images",
        ],
        indicators=[
            "Images using :latest or other mutable tags",
            "Unsigned images deployed to production",
            "Base images from untrusted or unknown registries",
            "Secrets or credentials embedded in image layers",
            "Images with known critical CVEs deployed",
            "Registry accessible without authentication",
        ],
        tools=["trivy", "grype", "cosign", "snyk-container",
               "docker-bench-security", "dive"],
        commands=[
            "trivy image --severity CRITICAL,HIGH <image>",
            "grype <image> --fail-on critical",
            "cosign verify <image>",
            "dive <image>",
            "docker history --no-trunc <image>",
            "docker-bench-security.sh",
        ],
        mitre_ids=["T1195.002"],
        severity="high",
    ),
    ContainerPattern(
        name="Network Policy Bypass",
        attack_type=ContainerAttackType.NETWORK_POLICY,
        description=(
            "Bypassing Kubernetes network policies: missing default-deny, "
            "pod-to-pod communication exploitation, service mesh misconfiguration, "
            "DNS exfiltration, and metadata API access."
        ),
        detection_strategies=[
            "Check if default-deny network policies exist",
            "Test pod-to-pod communication across namespaces",
            "Check if pods can access cloud metadata API (169.254.169.254)",
            "Verify service mesh mTLS is enforced (not permissive)",
            "Test DNS exfiltration from pods (external DNS queries)",
            "Check for NodePort services exposing internal services",
            "Verify egress network policies restrict outbound traffic",
            "Test if CoreDNS allows arbitrary external resolution",
        ],
        indicators=[
            "No NetworkPolicy resources in namespace",
            "Pods can reach cloud metadata endpoint",
            "Cross-namespace communication unrestricted",
            "Service mesh in permissive mTLS mode",
            "External DNS queries from application pods",
            "NodePort services on all nodes",
        ],
        tools=["kubectl", "netpol-viewer", "cilium", "calico",
               "istioctl", "nmap"],
        commands=[
            "kubectl get networkpolicies --all-namespaces",
            "kubectl exec -it test-pod -- curl http://169.254.169.254/latest/meta-data/",
            "kubectl exec -it test-pod -- nslookup evil.com",
            "kubectl exec -it test-pod -- curl http://svc.other-namespace.svc.cluster.local",
            "istioctl proxy-status",
            "kubectl get svc --all-namespaces -o json | jq '.items[] | select(.spec.type==\"NodePort\")'",
        ],
        mitre_ids=["T1046", "T1040"],
        severity="high",
    ),
    ContainerPattern(
        name="Secrets Management",
        attack_type=ContainerAttackType.SECRETS_MGMT,
        description=(
            "Attacking Kubernetes secrets: etcd plaintext storage, "
            "env var exposure, configmap secrets, mounted secret volumes, "
            "and service account token abuse."
        ),
        detection_strategies=[
            "Check if etcd data is encrypted at rest",
            "Scan pod specs for secrets in environment variables",
            "Check for secrets in ConfigMaps instead of Secrets",
            "Verify RBAC restricts secret access per namespace",
            "Check if service account tokens auto-mount unnecessarily",
            "Scan container filesystem for mounted secret volumes",
            "Check for secrets in container logs or stdout",
            "Verify external secrets operator configuration",
        ],
        indicators=[
            "etcd data not encrypted at rest",
            "Secrets passed as environment variables in pod spec",
            "Credentials stored in ConfigMaps (not Secrets)",
            "All pods can read secrets in namespace",
            "Service account tokens auto-mounted in all pods",
            "Secrets visible in container logs",
        ],
        tools=["kubectl", "kube-bench", "kubesec", "trivy", "vault"],
        commands=[
            "kubectl get secrets -o json | jq '.items[].data | keys'",
            "kubectl get pods -o json | jq '.items[].spec.containers[].env[] | select(.valueFrom.secretKeyRef)'",
            "kubectl get configmaps -o json | jq '.items[].data | keys'",
            "ETCDCTL_API=3 etcdctl get /registry/secrets --prefix --keys-only",
            "kubectl get sa --all-namespaces -o json | jq '.items[] | select(.automountServiceAccountToken!=false)'",
        ],
        mitre_ids=["T1552.007"],
        severity="high",
    ),
]


def build_container_k8s_prompt(
    focus_type: ContainerAttackType | None = None,
    max_patterns: int = 5,
) -> str:
    """Build LLM prompt with container/K8s security knowledge."""
    lines = ["## Container & Kubernetes Security Knowledge\n"]

    patterns = CONTAINER_PATTERNS
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
