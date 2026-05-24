"""Insider threat detection knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class InsiderThreatType(str, Enum):
    DATA_EXFIL = "data_exfiltration"
    PRIVILEGE_ABUSE = "privilege_abuse"
    SABOTAGE = "sabotage"
    CREDENTIAL_SHARING = "credential_sharing"
    POLICY_VIOLATION = "policy_violation"

@dataclass
class InsiderPattern:
    name: str = ""
    threat_type: InsiderThreatType = InsiderThreatType.DATA_EXFIL
    description: str = ""
    detection_methods: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.threat_type.value, "severity": self.severity}

INSIDER_PATTERNS: list[InsiderPattern] = [
    InsiderPattern(name="Data Exfiltration Detection", threat_type=InsiderThreatType.DATA_EXFIL, description="Detect unauthorized data transfers: USB, cloud uploads, email attachments, print jobs, screen captures, encrypted archives to personal storage.", detection_methods=["Monitor USB device connections and file copies", "Track cloud storage uploads (personal Dropbox/Drive)", "Analyze email attachment patterns and sizes", "Monitor print job volumes for sensitive documents", "Detect large archive creation (zip/7z/rar)", "Track after-hours file access patterns", "Monitor DNS for data exfiltration tunneling", "Check for unauthorized remote access tools"], indicators=["Unusual volume of file downloads/copies", "Large email attachments to personal addresses", "USB device usage outside normal patterns", "Cloud storage sync to unauthorized accounts", "Archive creation in temp directories", "After-hours access to sensitive file shares"], tools=["dlp-solutions", "ueba", "siem", "endpoint-monitor"], commands=["Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663} | Where-Object {$_.Message -match 'removable'}"], severity="critical"),
    InsiderPattern(name="Privilege Abuse Detection", threat_type=InsiderThreatType.PRIVILEGE_ABUSE, description="Detect misuse of elevated privileges: unauthorized database queries, accessing other users' files, modifying audit logs, creating backdoor accounts.", detection_methods=["Monitor privileged account usage patterns", "Track database query patterns for anomalies", "Detect access to files outside role scope", "Monitor audit log modifications", "Track new account creation by admins", "Analyze privilege escalation patterns", "Check for unauthorized group membership changes", "Monitor service account usage from workstations"], indicators=["Admin accessing user mailboxes", "Database queries outside normal scope", "Audit log clearing or modification", "New admin accounts created without ticket", "Service account used interactively", "Bulk permission changes"], tools=["varonis", "cyberark", "sailpoint"], commands=["Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672} | Select-Object -First 50"], severity="critical"),
    InsiderPattern(name="Sabotage Detection", threat_type=InsiderThreatType.SABOTAGE, description="Detect intentional damage: mass file deletion, configuration changes, backdoor installation, logic bombs, infrastructure disruption.", detection_methods=["Monitor mass file deletion events", "Track critical configuration changes", "Detect scheduled task creation with delayed execution", "Monitor source code repository force-pushes", "Track infrastructure teardown commands", "Detect backup deletion or corruption", "Monitor for logic bomb patterns in code commits", "Track DNS/firewall rule modifications"], indicators=["Mass file deletion in short timeframe", "Critical service configuration changes", "Scheduled tasks with future execution dates", "Force-push to main branch deleting history", "Backup deletion or encryption", "Firewall rules allowing unauthorized access"], tools=["siem", "git-audit", "backup-monitor"], commands=["git log --diff-filter=D --summary | head -50", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4660} | Select-Object -First 20"], severity="critical"),
    InsiderPattern(name="Credential Sharing Detection", threat_type=InsiderThreatType.CREDENTIAL_SHARING, description="Detect credential sharing: concurrent logins from different locations, password sharing via chat, shared service accounts, MFA token sharing.", detection_methods=["Detect concurrent sessions from different IPs/locations", "Monitor for impossible travel (login from two countries)", "Track shared account usage patterns", "Detect credentials in chat/email messages", "Monitor for password manager sharing", "Track MFA device registration anomalies"], indicators=["Same account active from multiple IPs simultaneously", "Impossible travel between login locations", "Credentials found in Slack/Teams messages", "Multiple devices registered for single user MFA", "Login patterns suggesting shared accounts"], tools=["azure-ad-audit", "okta-syslog", "slack-audit"], commands=["az ad signin list --filter 'status/errorCode eq 0' --query '[].{User:userPrincipalName,IP:ipAddress,Location:location.city}'"], severity="high"),
    InsiderPattern(name="Policy Violation Detection", threat_type=InsiderThreatType.POLICY_VIOLATION, description="Detect policy violations: unauthorized software installation, VPN/proxy usage, personal device connections, shadow IT, unauthorized cloud services.", detection_methods=["Monitor software installation events", "Detect VPN/proxy/Tor usage on corporate network", "Track BYOD connections to corporate resources", "Discover shadow IT cloud services via DNS/proxy logs", "Monitor for unauthorized remote access tools", "Detect policy bypass attempts (proxy avoidance)", "Track software license violations", "Monitor for cryptocurrency mining"], indicators=["Unauthorized software in process list", "Tor/VPN traffic from corporate devices", "Unmanaged devices on corporate network", "DNS queries to unauthorized SaaS services", "Remote desktop tools (TeamViewer, AnyDesk)", "High CPU usage suggesting crypto mining"], tools=["nac", "proxy-logs", "casb"], commands=["netstat -tlnp | grep -E '(9050|1080|8080)'", "ps aux | sort -nk 3 -r | head -10"], severity="medium"),
]

def build_insider_threat_prompt(focus_type: InsiderThreatType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Insider Threat Detection Knowledge\n"]
    patterns = INSIDER_PATTERNS if not focus_type else [p for p in INSIDER_PATTERNS if p.threat_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nDetection:")
        for d in p.detection_methods[:4]:
            lines.append(f"  - {d}")
        lines.append("")
    return "\n".join(lines)
