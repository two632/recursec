"""Zero trust architecture assessment knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class ZeroTrustPillar(str, Enum):
    IDENTITY = "identity"
    DEVICES = "devices"
    NETWORK = "network"
    APPLICATIONS = "applications"
    DATA = "data"

@dataclass
class ZeroTrustPattern:
    name: str = ""
    pillar: ZeroTrustPillar = ZeroTrustPillar.IDENTITY
    description: str = ""
    assessment_checks: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "pillar": self.pillar.value, "severity": self.severity}

ZERO_TRUST_PATTERNS: list[ZeroTrustPattern] = [
    ZeroTrustPattern(name="Identity Verification", pillar=ZeroTrustPillar.IDENTITY, description="Verify every identity: MFA enforcement, conditional access, privileged identity management, just-in-time access, continuous authentication, session management, identity federation security.", assessment_checks=["MFA enforced for all users including admins", "Conditional access policies (location, device, risk)", "Privileged Identity Management (PIM) with JIT elevation", "Password policy strength and rotation", "Service account inventory and credential rotation", "SSO/federation configuration (SAML, OIDC)", "Session timeout and re-authentication policies", "Identity governance and access reviews"], weaknesses=["MFA not enforced for service accounts", "Overly broad conditional access exceptions", "Standing admin privileges without JIT", "Weak password policies", "Stale service account credentials"], tools=["azuread-audit", "pingidentity", "okta-api"], commands=["az ad user list --query '[].{Name:displayName,MFA:strongAuthenticationDetail}'", "Get-MsolUser -All | Where-Object {$_.StrongAuthenticationMethods.Count -eq 0}"], severity="critical"),
    ZeroTrustPattern(name="Device Trust", pillar=ZeroTrustPillar.DEVICES, description="Verify device health before granting access: compliance checks, endpoint detection, patch status, disk encryption, certificate-based device identity.", assessment_checks=["Device compliance policies enforced", "Endpoint detection and response (EDR) deployed", "OS and application patch compliance", "Disk encryption (BitLocker/FileVault) enforced", "Device certificate enrollment (SCEP/EST)", "Mobile device management (MDM) enrollment", "BYOD vs corporate device policies", "Device health attestation"], weaknesses=["Unmanaged devices accessing corporate resources", "EDR gaps on certain device types", "Patch compliance below threshold", "No disk encryption enforcement"], tools=["intune", "jamf", "crowdstrike", "tanium"], commands=["Get-IntuneDeviceComplianceStatus | Where-Object {$_.ComplianceState -ne 'compliant'}"], severity="high"),
    ZeroTrustPattern(name="Network Microsegmentation", pillar=ZeroTrustPillar.NETWORK, description="Microsegment network: default deny, east-west traffic inspection, software-defined perimeter, encrypted tunnels, network access control.", assessment_checks=["Default deny network policies", "East-west traffic inspection and logging", "Microsegmentation between workloads", "Software-defined perimeter (SDP) implementation", "Encrypted communication (mTLS) between services", "Network access control (802.1X) for wired/wireless", "DNS filtering and inspection", "VPN replacement with ZTNA"], weaknesses=["Flat network with no segmentation", "No east-west traffic inspection", "Legacy protocols without encryption", "Overly permissive firewall rules"], tools=["calico", "istio", "paloalto", "zscaler"], commands=["kubectl get networkpolicies -A", "iptables -L -n --line-numbers", "nmap -sS -p- --reason target"], severity="high"),
    ZeroTrustPattern(name="Application Security", pillar=ZeroTrustPillar.APPLICATIONS, description="Secure applications: API gateway enforcement, runtime application self-protection, secure access service edge, application-level encryption, code signing.", assessment_checks=["API gateway with authentication/authorization", "Runtime application self-protection (RASP)", "Web application firewall (WAF) with custom rules", "Application-level encryption (field-level)", "Code signing and integrity verification", "Secure software development lifecycle (SSDLC)", "Third-party application risk assessment", "Application access based on identity + context"], weaknesses=["Direct application access bypassing gateway", "No RASP/WAF for internal applications", "Unsigned code deployment", "No application-level encryption"], tools=["kong", "envoy", "modsecurity", "falco"], commands=["curl -k -H 'Authorization: Bearer test' https://api/v1/admin", "nikto -h https://target"], severity="high"),
    ZeroTrustPattern(name="Data Protection", pillar=ZeroTrustPillar.DATA, description="Protect data: classification, DLP, encryption at rest/transit, rights management, data access governance, backup integrity verification.", assessment_checks=["Data classification and labeling", "Data loss prevention (DLP) policies", "Encryption at rest (AES-256) for all datastores", "Encryption in transit (TLS 1.3) for all connections", "Information rights management (IRM)", "Data access governance and audit trails", "Backup encryption and integrity verification", "Data residency and sovereignty compliance"], weaknesses=["Unclassified sensitive data", "DLP gaps in cloud storage", "Unencrypted databases", "No data access audit trail"], tools=["microsoft-purview", "aws-macie", "hashicorp-vault"], commands=["aws macie2 get-findings --finding-ids $(aws macie2 list-findings --query 'findingIds[0]')", "vault secrets list"], severity="critical"),
]

def build_zero_trust_prompt(focus_pillar: ZeroTrustPillar | None = None, max_patterns: int = 5) -> str:
    lines = ["## Zero Trust Architecture Assessment\n"]
    patterns = ZERO_TRUST_PATTERNS if not focus_pillar else [p for p in ZERO_TRUST_PATTERNS if p.pillar == focus_pillar]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nChecks:")
        for c in p.assessment_checks[:4]:
            lines.append(f"  - {c}")
        lines.append("\nWeaknesses:")
        for w in p.weaknesses[:3]:
            lines.append(f"  ! {w}")
        lines.append("")
    return "\n".join(lines)
