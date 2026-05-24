"""Kubernetes and container orchestration security KB.

Deep knowledge about K8s security:
1. Cluster security assessment
2. Pod security and escape
3. RBAC and service account attacks
4. Network policy assessment
5. Supply chain and image security
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class K8sPattern:
    """A Kubernetes security pattern."""
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


K8S_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "k8s-001", "name": "Cluster Security Assessment",
        "category": "cluster", "severity": "critical",
        "desc": "Kubernetes cluster security.",
        "detection": (
            "K8S CLUSTER SECURITY:\n"
            "API SERVER:\n"
            "  # Check anonymous auth\n"
            "  kubectl auth can-i --list --as=system:anonymous\n"
            "  # Check API server exposure\n"
            "  # Insecure port (6443/8080)\n"
            "  # Authentication methods\n"
            "  # Audit logging\n"
            "  # Admission controllers\n"
            "ETCD:\n"
            "  # Direct access (2379/2380)\n"
            "  etcdctl --endpoints=http://TARGET:2379 get / --prefix\n"
            "  # Encryption at rest\n"
            "  # mTLS between nodes\n"
            "  # Backup security\n"
            "KUBELET:\n"
            "  # Anonymous access (10250)\n"
            "  curl -sk https://TARGET:10250/pods\n"
            "  # Read-only port (10255)\n"
            "  curl http://TARGET:10255/pods\n"
            "  # exec via kubelet API\n"
            "CIS BENCHMARK:\n"
            "  # kube-bench (CIS checks)\n"
            "  kube-bench run --targets=master\n"
            "  kube-bench run --targets=node\n"
            "  # kubeaudit\n"
            "  kubeaudit all\n"
            "  # kubesec (manifest scanning)\n"
            "  kubesec scan deployment.yaml\n"
            "DASHBOARD:\n"
            "  - Default/no auth dashboard\n"
            "  - Token exposure\n"
            "  - Cluster admin dashboard SA\n"
            "TOOLS:\n"
            "  kube-bench, kubeaudit, kubesec, kubectl"
        ),
        "tools": ["kube-bench"],
    },
    {
        "id": "k8s-002", "name": "Pod Security and Escape",
        "category": "pod_security", "severity": "critical",
        "desc": "Pod security and container escape.",
        "detection": (
            "POD SECURITY & ESCAPE:\n"
            "PRIVILEGED CONTAINERS:\n"
            "  # Check for privileged pods\n"
            "  kubectl get pods -o json | jq '.items[].spec.containers[].securityContext'\n"
            "  # Privileged = full host access\n"
            "  # Container escape:\n"
            "  #   mount host filesystem\n"
            "  #   nsenter to host\n"
            "  #   cgroup escape\n"
            "HOST PATHS:\n"
            "  - hostPath volume mounts\n"
            "  - /var/run/docker.sock mount\n"
            "  - /proc host mount\n"
            "  - /sys host mount\n"
            "CAPABILITIES:\n"
            "  DANGEROUS:\n"
            "    - SYS_ADMIN (mount, namespace)\n"
            "    - SYS_PTRACE (process injection)\n"
            "    - NET_ADMIN (network control)\n"
            "    - DAC_OVERRIDE (bypass file perms)\n"
            "  CHECK:\n"
            "    cat /proc/1/status | grep Cap\n"
            "    capsh --decode=<hex_value>\n"
            "POD SECURITY STANDARDS:\n"
            "  - Privileged (unrestricted)\n"
            "  - Baseline (minimal restrictions)\n"
            "  - Restricted (hardened)\n"
            "ESCAPE TECHNIQUES:\n"
            "  - Core pattern exploitation\n"
            "  - Kernel exploit from container\n"
            "  - Docker socket abuse\n"
            "  - cgroup release_agent\n"
            "  - runc CVE exploitation\n"
            "TOOLS:\n"
            "  kubectl, CDK (container escape), deepce"
        ),
        "tools": ["kubectl"],
    },
    {
        "id": "k8s-003", "name": "RBAC and Service Account Attacks",
        "category": "rbac", "severity": "critical",
        "desc": "RBAC and service account attacks.",
        "detection": (
            "RBAC & SERVICE ACCOUNTS:\n"
            "ENUMERATION:\n"
            "  # Check current permissions\n"
            "  kubectl auth can-i --list\n"
            "  # Check specific action\n"
            "  kubectl auth can-i create pods\n"
            "  # List all roles\n"
            "  kubectl get clusterroles\n"
            "  kubectl get roles -A\n"
            "  # List bindings\n"
            "  kubectl get clusterrolebindings\n"
            "DANGEROUS PERMISSIONS:\n"
            "  - create pods (run anything)\n"
            "  - create deployments (persistence)\n"
            "  - get secrets (credential theft)\n"
            "  - create serviceaccounts/token\n"
            "  - impersonate users\n"
            "  - escalate (grant any role)\n"
            "  - bind (attach any role)\n"
            "  - create clusterrolebinding\n"
            "SERVICE ACCOUNT TOKEN:\n"
            "  # Automounted token\n"
            "  cat /var/run/secrets/kubernetes.io/serviceaccount/token\n"
            "  # Use token\n"
            "  kubectl --token=$TOKEN --server=$API auth can-i --list\n"
            "PRIVESC PATHS:\n"
            "  - Token → list secrets → get admin token\n"
            "  - Create pod → mount host → root\n"
            "  - Impersonate → cluster-admin\n"
            "  - RBAC misconfiguration chains\n"
            "TOOLS:\n"
            "  kubectl, rbac-tool, rback, kubectl-who-can"
        ),
        "tools": ["kubectl"],
    },
    {
        "id": "k8s-004", "name": "Network Policy Assessment",
        "category": "network", "severity": "high",
        "desc": "K8s network policy assessment.",
        "detection": (
            "K8S NETWORK POLICY:\n"
            "ASSESSMENT:\n"
            "  # Check for network policies\n"
            "  kubectl get networkpolicies -A\n"
            "  # Default: all pods can talk to all pods\n"
            "  # Check if CNI supports network policies\n"
            "  #   Calico, Cilium, Weave: yes\n"
            "  #   Flannel: no (by default)\n"
            "TESTING:\n"
            "  # Pod-to-pod connectivity\n"
            "  kubectl exec -it test-pod -- curl svc.namespace.svc\n"
            "  # Pod-to-external\n"
            "  kubectl exec -it test-pod -- curl https://external.com\n"
            "  # DNS access\n"
            "  kubectl exec -it test-pod -- nslookup kubernetes\n"
            "COMMON ISSUES:\n"
            "  - No network policies (flat network)\n"
            "  - Overly permissive policies\n"
            "  - Missing egress restrictions\n"
            "  - DNS not restricted\n"
            "  - Metadata API accessible (169.254.169.254)\n"
            "  - Cross-namespace access allowed\n"
            "SERVICE MESH:\n"
            "  - Istio mTLS enforcement\n"
            "  - Authorization policies\n"
            "  - Traffic encryption\n"
            "  - Sidecar injection\n"
            "TOOLS:\n"
            "  kubectl, netshoot, Cilium Hubble"
        ),
        "tools": ["kubectl"],
    },
    {
        "id": "k8s-005", "name": "Supply Chain and Image Security",
        "category": "supply_chain", "severity": "high",
        "desc": "Container supply chain security.",
        "detection": (
            "CONTAINER SUPPLY CHAIN:\n"
            "IMAGE SCANNING:\n"
            "  # Trivy\n"
            "  trivy image TARGET_IMAGE:TAG\n"
            "  # Grype\n"
            "  grype TARGET_IMAGE:TAG\n"
            "  # Snyk\n"
            "  snyk container test TARGET_IMAGE:TAG\n"
            "IMAGE POLICIES:\n"
            "  - Only pull from trusted registries\n"
            "  - Image signing (cosign/Notary)\n"
            "  - Admission control (OPA/Kyverno)\n"
            "  - No latest tag\n"
            "  - Digest-based references\n"
            "  - Minimal base images (distroless)\n"
            "REGISTRY SECURITY:\n"
            "  - Private registry access control\n"
            "  - Image scanning on push\n"
            "  - Vulnerability thresholds\n"
            "  - Retention policies\n"
            "  - Pull secret management\n"
            "SBOM (Software Bill of Materials):\n"
            "  # Generate SBOM\n"
            "  syft TARGET_IMAGE:TAG -o spdx-json\n"
            "  # SLSA provenance\n"
            "  # Verify signatures\n"
            "  cosign verify TARGET_IMAGE:TAG\n"
            "ADMISSION CONTROL:\n"
            "  - OPA Gatekeeper policies\n"
            "  - Kyverno policies\n"
            "  - ImagePolicyWebhook\n"
            "  - Block unsigned images\n"
            "TOOLS:\n"
            "  Trivy, Grype, cosign, syft, OPA"
        ),
        "tools": ["trivy", "grype"],
    },
]


class KubernetesSecurityKB:
    """Kubernetes security knowledge base.

    Provides K8s security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, K8sPattern] = {}
        self._log = logger.bind(component="k8s_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load K8s patterns."""
        for data in K8S_PATTERNS:
            pattern = K8sPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[K8sPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_k8s_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build K8s security prompt."""
        lines = ["## Kubernetes Security\n"]
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
