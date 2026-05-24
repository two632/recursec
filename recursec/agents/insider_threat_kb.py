"""Insider threat detection knowledge base.

Behavioral indicators, detection patterns, and response strategies for:
- Malicious insider activity (data exfiltration, sabotage)
- Negligent insider behavior (misconfigurations, policy violations)
- Compromised insider accounts
- Privilege abuse and escalation
- Social engineering against insiders
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class InsiderThreatPattern:
    name: str = ""
    category: str = ""
    severity: str = "high"
    indicators: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    response: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "cat": self.category, "sev": self.severity}


INSIDER_THREAT_PATTERNS: list[InsiderThreatPattern] = [
    InsiderThreatPattern(
        name="Data Exfiltration via Email",
        category="exfiltration",
        severity="critical",
        indicators=[
            "Large attachments sent to personal email addresses",
            "Unusual email volume outside business hours",
            "Emails to domains not in approved vendor list",
            "Encrypted attachments to external recipients",
            "Auto-forwarding rules to external addresses",
        ],
        detection=[
            "DLP rules on email gateway for sensitive data patterns",
            "Monitor attachment sizes exceeding baseline thresholds",
            "Alert on auto-forward rules to external domains",
            "Analyze email metadata for anomalous patterns",
            "Track email volume per user vs historical baseline",
        ],
        response=[
            "Quarantine suspicious emails immediately",
            "Interview employee with HR present",
            "Forensic analysis of workstation",
            "Review access logs for data accessed prior to exfil",
            "Revoke access if confirmed malicious",
        ],
    ),
    InsiderThreatPattern(
        name="Unauthorized Cloud Storage",
        category="exfiltration",
        severity="high",
        indicators=[
            "Uploads to personal Dropbox/Google Drive/OneDrive",
            "Use of unauthorized file sharing services",
            "Large data transfers to cloud storage APIs",
            "Installation of cloud sync clients on corporate devices",
            "DNS queries to known cloud storage domains",
        ],
        detection=[
            "CASB policies blocking unauthorized cloud services",
            "Web proxy logs for cloud storage domain access",
            "DNS monitoring for known cloud storage services",
            "Endpoint monitoring for cloud sync client installation",
            "Network DLP for outbound data to cloud APIs",
        ],
        response=[
            "Block access to unauthorized cloud services",
            "Investigate scope of data uploaded",
            "Determine if sensitive/classified data was exposed",
            "Review employee's data access patterns",
        ],
    ),
    InsiderThreatPattern(
        name="Privilege Escalation Abuse",
        category="privilege_abuse",
        severity="critical",
        indicators=[
            "Accessing systems outside job role",
            "Requesting elevated permissions without justification",
            "Using admin accounts for non-admin tasks",
            "Accessing HR/finance systems from IT accounts",
            "Modifying audit logs or disabling monitoring",
        ],
        detection=[
            "UEBA baseline for normal access patterns per role",
            "Alert on cross-department resource access",
            "Monitor for audit log modifications",
            "Track privilege elevation requests and approvals",
            "Analyze access patterns against job function matrix",
        ],
        response=[
            "Immediately revoke excess privileges",
            "Review all actions taken with elevated access",
            "Implement just-in-time privilege access",
            "Audit all privilege escalation approvals",
        ],
    ),
    InsiderThreatPattern(
        name="Sabotage via Code/Configuration",
        category="sabotage",
        severity="critical",
        indicators=[
            "Unusual code changes before resignation",
            "Deletion of critical files or repositories",
            "Modification of security configurations",
            "Introduction of backdoors in codebase",
            "Disabling monitoring or alerting systems",
        ],
        detection=[
            "Code review requirements for all critical changes",
            "Monitor for large-scale deletions in version control",
            "Alert on security configuration changes",
            "Track departing employee code commits closely",
            "Automated backdoor detection in CI/CD pipeline",
        ],
        response=[
            "Roll back unauthorized changes immediately",
            "Full code audit of recent commits by employee",
            "Revoke all access immediately upon suspicion",
            "Legal hold on all employee devices",
        ],
    ),
    InsiderThreatPattern(
        name="Social Engineering Against Insiders",
        category="social_engineering",
        severity="high",
        indicators=[
            "Employee reporting unusual contact from external parties",
            "Requests for credentials via phone/chat",
            "Phishing targeting specific employees with internal knowledge",
            "Unusual requests from spoofed executive email",
            "Physical tailgating or impersonation attempts",
        ],
        detection=[
            "Security awareness training with phishing simulations",
            "Email authentication (DMARC/DKIM/SPF) enforcement",
            "Behavioral analysis for out-of-pattern credential sharing",
            "Physical access logs correlated with badge holder identity",
            "Report mechanisms for suspicious contacts",
        ],
        response=[
            "Isolate affected accounts",
            "Reset credentials for targeted employees",
            "Investigate scope of information disclosed",
            "Update security awareness training",
        ],
    ),
]

DOMAIN_META = {
    "domain": "insider_threat",
    "patterns": len(INSIDER_THREAT_PATTERNS),
    "categories": ["exfiltration", "privilege_abuse", "sabotage", "social_engineering"],
}


def build_insider_threat_kb_prompt() -> str:
    """Build LLM prompt with insider threat knowledge."""
    lines = ["## Insider Threat Detection Knowledge"]
    for pat in INSIDER_THREAT_PATTERNS:
        lines.append(f"\n### {pat.name} [{pat.severity}]")
        lines.append(f"Category: {pat.category}")
        lines.append("Indicators:")
        for ind in pat.indicators[:3]:
            lines.append(f"  - {ind}")
        lines.append("Detection:")
        for det in pat.detection[:2]:
            lines.append(f"  - {det}")
    return "\n".join(lines)
