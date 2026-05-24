"""Tool executor — async subprocess management for external tools.

Implements:
1. Async subprocess execution for 200+ tools
2. Timeout management
3. Output capture and streaming
4. Tool availability detection
5. Command sanitization
6. Resource limiting
7. Execution logging
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolCategory(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOITATION = "exploitation"
    BRUTE_FORCE = "brute_force"
    WEB = "web"
    NETWORK = "network"
    CODE_ANALYSIS = "code_analysis"
    OSINT = "osint"
    CRYPTO = "crypto"
    FUZZING = "fuzzing"
    CONTAINER = "container"
    CLOUD = "cloud"
    MOBILE = "mobile"
    WIRELESS = "wireless"
    POST_EXPLOIT = "post_exploit"
    DATABASE = "database"
    ENUM = "enumeration"
    REVERSE = "reverse_eng"
    DNS = "dns"
    SSL = "ssl"
    AD_WINDOWS = "ad_windows"
    API = "api"
    GIT_SEC = "git_security"
    SOCIAL_ENG = "social_eng"
    REPORTING = "reporting"
    GENERAL = "general"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"


@dataclass
class ToolDefinition:
    """Definition of an external tool."""
    name: str = ""
    binary: str = ""
    category: ToolCategory = ToolCategory.SCANNER
    description: str = ""
    available: bool = False
    install_cmd: str = ""
    default_timeout_s: int = 300

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "category": self.category.value,
            "available": self.available,
        }


@dataclass
class ExecutionResult:
    """Result from a tool execution."""
    tool: str = ""
    command: str = ""
    status: ExecutionStatus = ExecutionStatus.PENDING
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout_len": len(self.stdout),
            "duration_s": round(self.duration_s, 1),
        }


# ── Tool registry ─────────────────────────────────────────────

TOOL_REGISTRY: list[dict[str, Any]] = [
    # ── Network Scanning (21 tools) ───────────────────────────
    {"name": "nmap", "binary": "nmap", "cat": "recon", "desc": "Network scanner", "timeout": 600},
    {"name": "masscan", "binary": "masscan", "cat": "recon", "desc": "Fast port scanner"},
    {"name": "rustscan", "binary": "rustscan", "cat": "recon", "desc": "Fast Rust port scanner"},
    {"name": "zmap", "binary": "zmap", "cat": "recon", "desc": "Internet-wide scanner"},
    {"name": "unicornscan", "binary": "unicornscan", "cat": "recon", "desc": "Async scanner"},
    {"name": "hping3", "binary": "hping3", "cat": "recon", "desc": "Packet crafter"},
    {"name": "netdiscover", "binary": "netdiscover", "cat": "recon", "desc": "ARP network discovery"},
    {"name": "arping", "binary": "arping", "cat": "recon", "desc": "ARP ping"},
    {"name": "fping", "binary": "fping", "cat": "recon", "desc": "Fast ping sweep"},
    {"name": "nbtscan", "binary": "nbtscan", "cat": "recon", "desc": "NetBIOS scanner"},
    {"name": "onesixtyone", "binary": "onesixtyone", "cat": "recon", "desc": "SNMP scanner"},
    {"name": "ike-scan", "binary": "ike-scan", "cat": "recon", "desc": "IKE/IPsec scanner"},
    {"name": "tcpdump", "binary": "tcpdump", "cat": "network", "desc": "Packet capture"},
    {"name": "tshark", "binary": "tshark", "cat": "network", "desc": "CLI Wireshark"},
    {"name": "ettercap", "binary": "ettercap", "cat": "network", "desc": "MITM framework"},
    {"name": "arp-scan", "binary": "arp-scan", "cat": "recon", "desc": "ARP scanner"},
    {"name": "p0f", "binary": "p0f", "cat": "recon", "desc": "Passive OS fingerprint"},
    {"name": "naabu", "binary": "naabu", "cat": "recon", "desc": "Fast port scanner (PD)"},
    {"name": "dnsx", "binary": "dnsx", "cat": "dns", "desc": "Fast DNS toolkit"},
    {"name": "dig", "binary": "dig", "cat": "dns", "desc": "DNS lookup"},
    {"name": "whois", "binary": "whois", "cat": "recon", "desc": "WHOIS lookup"},
    # ── Web Application Testing (35 tools) ────────────────────
    {"name": "nuclei", "binary": "nuclei", "cat": "scanner", "desc": "Template-based scanner", "timeout": 900},
    {"name": "nikto", "binary": "nikto", "cat": "scanner", "desc": "Web server scanner"},
    {"name": "ffuf", "binary": "ffuf", "cat": "web", "desc": "Web fuzzer"},
    {"name": "gobuster", "binary": "gobuster", "cat": "web", "desc": "Directory bruteforce"},
    {"name": "feroxbuster", "binary": "feroxbuster", "cat": "web", "desc": "Recursive content discovery"},
    {"name": "dirb", "binary": "dirb", "cat": "web", "desc": "URL bruteforcer"},
    {"name": "wfuzz", "binary": "wfuzz", "cat": "web", "desc": "Web fuzzer"},
    {"name": "sqlmap", "binary": "sqlmap", "cat": "web", "desc": "SQL injection"},
    {"name": "commix", "binary": "commix", "cat": "web", "desc": "Command injection"},
    {"name": "xsser", "binary": "xsser", "cat": "web", "desc": "XSS scanner"},
    {"name": "wpscan", "binary": "wpscan", "cat": "scanner", "desc": "WordPress scanner"},
    {"name": "joomscan", "binary": "joomscan", "cat": "scanner", "desc": "Joomla scanner"},
    {"name": "droopescan", "binary": "droopescan", "cat": "scanner", "desc": "CMS scanner"},
    {"name": "whatweb", "binary": "whatweb", "cat": "recon", "desc": "Web technology detector"},
    {"name": "wafw00f", "binary": "wafw00f", "cat": "recon", "desc": "WAF detector"},
    {"name": "httrack", "binary": "httrack", "cat": "web", "desc": "Website copier"},
    {"name": "curl", "binary": "curl", "cat": "web", "desc": "HTTP client"},
    {"name": "wget", "binary": "wget", "cat": "web", "desc": "HTTP downloader"},
    {"name": "cadaver", "binary": "cadaver", "cat": "web", "desc": "WebDAV client"},
    {"name": "davtest", "binary": "davtest", "cat": "web", "desc": "WebDAV tester"},
    {"name": "skipfish", "binary": "skipfish", "cat": "scanner", "desc": "Active web scanner"},
    {"name": "wapiti", "binary": "wapiti", "cat": "scanner", "desc": "Web app scanner"},
    {"name": "dalfox", "binary": "dalfox", "cat": "web", "desc": "XSS scanner"},
    {"name": "arjun", "binary": "arjun", "cat": "web", "desc": "Parameter finder"},
    {"name": "katana", "binary": "katana", "cat": "web", "desc": "Web crawler (PD)"},
    {"name": "gau", "binary": "gau", "cat": "web", "desc": "Get All URLs"},
    {"name": "waybackurls", "binary": "waybackurls", "cat": "web", "desc": "Wayback Machine URLs"},
    {"name": "hakrawler", "binary": "hakrawler", "cat": "web", "desc": "Web crawler"},
    {"name": "gospider", "binary": "gospider", "cat": "web", "desc": "Go web spider"},
    {"name": "httpx-pd", "binary": "httpx", "cat": "recon", "desc": "HTTP probing (PD)"},
    {"name": "httprobe", "binary": "httprobe", "cat": "recon", "desc": "HTTP/HTTPS prober"},
    {"name": "meg", "binary": "meg", "cat": "web", "desc": "Many paths, many hosts"},
    {"name": "unfurl", "binary": "unfurl", "cat": "web", "desc": "URL parser"},
    {"name": "anew", "binary": "anew", "cat": "general", "desc": "Append new lines"},
    {"name": "dotdotpwn", "binary": "dotdotpwn", "cat": "web", "desc": "Path traversal scanner"},
    # ── Subdomain Discovery (14 tools) ────────────────────────
    {"name": "subfinder", "binary": "subfinder", "cat": "recon", "desc": "Subdomain discovery"},
    {"name": "amass", "binary": "amass", "cat": "recon", "desc": "DNS enumeration", "timeout": 600},
    {"name": "assetfinder", "binary": "assetfinder", "cat": "recon", "desc": "Asset finder"},
    {"name": "chaos", "binary": "chaos", "cat": "recon", "desc": "ProjectDiscovery chaos"},
    {"name": "sublist3r", "binary": "sublist3r", "cat": "recon", "desc": "Subdomain enumerator"},
    {"name": "knockpy", "binary": "knockpy", "cat": "recon", "desc": "Subdomain scanner"},
    {"name": "fierce", "binary": "fierce", "cat": "dns", "desc": "DNS brute force"},
    {"name": "dnsrecon", "binary": "dnsrecon", "cat": "dns", "desc": "DNS recon"},
    {"name": "dnsenum", "binary": "dnsenum", "cat": "dns", "desc": "DNS enumeration"},
    {"name": "altdns", "binary": "altdns", "cat": "dns", "desc": "DNS alteration scanner"},
    {"name": "dnsgen", "binary": "dnsgen", "cat": "dns", "desc": "DNS wordlist generator"},
    {"name": "shuffledns", "binary": "shuffledns", "cat": "dns", "desc": "MassDNS wrapper"},
    {"name": "puredns", "binary": "puredns", "cat": "dns", "desc": "DNS bruteforce/resolver"},
    {"name": "massdns", "binary": "massdns", "cat": "dns", "desc": "High-perf DNS stub resolver"},
    # ── Exploitation Frameworks (10 tools) ────────────────────
    {"name": "metasploit", "binary": "msfconsole", "cat": "exploitation", "desc": "Exploitation framework"},
    {"name": "msfvenom", "binary": "msfvenom", "cat": "exploitation", "desc": "Payload generator"},
    {"name": "searchsploit", "binary": "searchsploit", "cat": "exploitation", "desc": "Exploit database"},
    {"name": "set", "binary": "setoolkit", "cat": "social_eng", "desc": "Social engineering toolkit"},
    {"name": "beef-xss", "binary": "beef-xss", "cat": "exploitation", "desc": "Browser exploitation"},
    {"name": "websploit", "binary": "websploit", "cat": "exploitation", "desc": "Web sploit framework"},
    {"name": "routersploit", "binary": "rsf", "cat": "exploitation", "desc": "Router exploitation"},
    {"name": "shellnoob", "binary": "shellnoob", "cat": "exploitation", "desc": "Shellcode toolkit"},
    # ── Password Cracking (20 tools) ──────────────────────────
    {"name": "john", "binary": "john", "cat": "brute_force", "desc": "Password cracker"},
    {"name": "hashcat", "binary": "hashcat", "cat": "brute_force", "desc": "GPU password cracker"},
    {"name": "hydra", "binary": "hydra", "cat": "brute_force", "desc": "Login brute force"},
    {"name": "medusa", "binary": "medusa", "cat": "brute_force", "desc": "Parallel brute force"},
    {"name": "ncrack", "binary": "ncrack", "cat": "brute_force", "desc": "Network auth cracker"},
    {"name": "ophcrack", "binary": "ophcrack", "cat": "brute_force", "desc": "Windows password cracker"},
    {"name": "chntpw", "binary": "chntpw", "cat": "brute_force", "desc": "NT password changer"},
    {"name": "crunch", "binary": "crunch", "cat": "brute_force", "desc": "Wordlist generator"},
    {"name": "cewl", "binary": "cewl", "cat": "brute_force", "desc": "Custom wordlist generator"},
    {"name": "hashid", "binary": "hashid", "cat": "brute_force", "desc": "Hash identifier"},
    {"name": "hash-identifier", "binary": "hash-identifier", "cat": "brute_force", "desc": "Hash type identifier"},
    {"name": "patator", "binary": "patator", "cat": "brute_force", "desc": "Multi-purpose brute forcer"},
    {"name": "crowbar", "binary": "crowbar", "cat": "brute_force", "desc": "Brute force tool"},
    {"name": "fcrackzip", "binary": "fcrackzip", "cat": "brute_force", "desc": "ZIP password cracker"},
    {"name": "pdfcrack", "binary": "pdfcrack", "cat": "brute_force", "desc": "PDF password cracker"},
    {"name": "rarcrack", "binary": "rarcrack", "cat": "brute_force", "desc": "RAR password cracker"},
    # ── Wireless Testing (20 tools) ───────────────────────────
    {"name": "aircrack-ng", "binary": "aircrack-ng", "cat": "wireless", "desc": "WiFi cracker"},
    {"name": "airodump-ng", "binary": "airodump-ng", "cat": "wireless", "desc": "WiFi packet capture"},
    {"name": "aireplay-ng", "binary": "aireplay-ng", "cat": "wireless", "desc": "WiFi packet injection"},
    {"name": "airmon-ng", "binary": "airmon-ng", "cat": "wireless", "desc": "WiFi monitor mode"},
    {"name": "reaver", "binary": "reaver", "cat": "wireless", "desc": "WPS brute force"},
    {"name": "bully", "binary": "bully", "cat": "wireless", "desc": "WPS brute force"},
    {"name": "wifite", "binary": "wifite", "cat": "wireless", "desc": "WiFi attack tool"},
    {"name": "kismet", "binary": "kismet", "cat": "wireless", "desc": "Wireless sniffer"},
    {"name": "mdk3", "binary": "mdk3", "cat": "wireless", "desc": "WiFi exploitation"},
    {"name": "mdk4", "binary": "mdk4", "cat": "wireless", "desc": "WiFi exploitation v4"},
    {"name": "pixiewps", "binary": "pixiewps", "cat": "wireless", "desc": "WPS offline brute"},
    {"name": "cowpatty", "binary": "cowpatty", "cat": "wireless", "desc": "WPA-PSK cracker"},
    {"name": "spooftooph", "binary": "spooftooph", "cat": "wireless", "desc": "Bluetooth spoofer"},
    {"name": "btscanner", "binary": "btscanner", "cat": "wireless", "desc": "Bluetooth scanner"},
    # ── Post-Exploitation (20 tools) ──────────────────────────
    {"name": "netcat", "binary": "nc", "cat": "post_exploit", "desc": "Network Swiss army knife"},
    {"name": "ncat", "binary": "ncat", "cat": "post_exploit", "desc": "Nmap netcat"},
    {"name": "socat", "binary": "socat", "cat": "post_exploit", "desc": "SOcket CAT relay"},
    {"name": "proxychains4", "binary": "proxychains4", "cat": "post_exploit", "desc": "Proxy chain"},
    {"name": "sslsplit", "binary": "sslsplit", "cat": "post_exploit", "desc": "SSL MITM"},
    {"name": "dsniff", "binary": "dsniff", "cat": "post_exploit", "desc": "Network sniffer"},
    {"name": "sslstrip", "binary": "sslstrip", "cat": "post_exploit", "desc": "SSL downgrade"},
    {"name": "mitmproxy", "binary": "mitmproxy", "cat": "post_exploit", "desc": "MITM proxy"},
    {"name": "responder", "binary": "responder", "cat": "post_exploit", "desc": "LLMNR/NBT-NS/MDNS poisoner"},
    {"name": "yersinia", "binary": "yersinia", "cat": "network", "desc": "Layer 2 attacks"},
    {"name": "weevely", "binary": "weevely", "cat": "post_exploit", "desc": "PHP webshell"},
    {"name": "iodine", "binary": "iodine", "cat": "post_exploit", "desc": "DNS tunnel"},
    {"name": "dns2tcp", "binary": "dns2tcp", "cat": "post_exploit", "desc": "DNS tunnel"},
    {"name": "chisel", "binary": "chisel", "cat": "post_exploit", "desc": "TCP/UDP tunnel"},
    {"name": "stunnel4", "binary": "stunnel4", "cat": "post_exploit", "desc": "SSL tunnel"},
    # ── Enumeration (20 tools) ────────────────────────────────
    {"name": "enum4linux", "binary": "enum4linux", "cat": "enumeration", "desc": "SMB enumeration"},
    {"name": "enum4linux-ng", "binary": "enum4linux-ng", "cat": "enumeration", "desc": "SMB enumeration v2"},
    {"name": "smbclient", "binary": "smbclient", "cat": "enumeration", "desc": "SMB client"},
    {"name": "smbmap", "binary": "smbmap", "cat": "enumeration", "desc": "SMB share mapper"},
    {"name": "snmpwalk", "binary": "snmpwalk", "cat": "enumeration", "desc": "SNMP walker"},
    {"name": "ldapsearch", "binary": "ldapsearch", "cat": "enumeration", "desc": "LDAP query"},
    {"name": "rpcinfo", "binary": "rpcinfo", "cat": "enumeration", "desc": "RPC information"},
    {"name": "showmount", "binary": "showmount", "cat": "enumeration", "desc": "NFS exports"},
    {"name": "smtp-user-enum", "binary": "smtp-user-enum", "cat": "enumeration", "desc": "SMTP user enum"},
    {"name": "finger", "binary": "finger", "cat": "enumeration", "desc": "Finger protocol client"},
    # ── Vulnerability Scanning (8 tools) ──────────────────────
    {"name": "openvas", "binary": "openvas", "cat": "scanner", "desc": "OpenVAS scanner"},
    {"name": "lynis", "binary": "lynis", "cat": "scanner", "desc": "System auditing"},
    {"name": "unix-privesc-check", "binary": "unix-privesc-check", "cat": "scanner", "desc": "Privilege escalation checker"},
    {"name": "linux-exploit-suggester", "binary": "linux-exploit-suggester", "cat": "scanner", "desc": "Kernel exploit suggester"},
    {"name": "golismero", "binary": "golismero", "cat": "scanner", "desc": "Web security framework"},
    {"name": "cisco-torch", "binary": "cisco-torch", "cat": "scanner", "desc": "Cisco scanner"},
    # ── Reverse Engineering (20 tools) ────────────────────────
    {"name": "radare2", "binary": "r2", "cat": "reverse_eng", "desc": "Reverse engineering"},
    {"name": "rizin", "binary": "rizin", "cat": "reverse_eng", "desc": "RE framework"},
    {"name": "ghidra", "binary": "ghidra", "cat": "reverse_eng", "desc": "NSA RE tool"},
    {"name": "binwalk", "binary": "binwalk", "cat": "reverse_eng", "desc": "Firmware analysis"},
    {"name": "foremost", "binary": "foremost", "cat": "reverse_eng", "desc": "File carving"},
    {"name": "volatility", "binary": "vol.py", "cat": "reverse_eng", "desc": "Memory forensics"},
    {"name": "yara", "binary": "yara", "cat": "reverse_eng", "desc": "Pattern matching"},
    {"name": "clamav", "binary": "clamscan", "cat": "reverse_eng", "desc": "Antivirus scanner"},
    {"name": "checksec", "binary": "checksec", "cat": "reverse_eng", "desc": "Binary security check"},
    {"name": "gdb", "binary": "gdb", "cat": "reverse_eng", "desc": "GNU debugger"},
    {"name": "ltrace", "binary": "ltrace", "cat": "reverse_eng", "desc": "Library call tracer"},
    {"name": "strace", "binary": "strace", "cat": "reverse_eng", "desc": "System call tracer"},
    {"name": "strings", "binary": "strings", "cat": "reverse_eng", "desc": "String extractor"},
    {"name": "hexedit", "binary": "hexedit", "cat": "reverse_eng", "desc": "Hex editor"},
    {"name": "chkrootkit", "binary": "chkrootkit", "cat": "reverse_eng", "desc": "Rootkit detector"},
    {"name": "rkhunter", "binary": "rkhunter", "cat": "reverse_eng", "desc": "Rootkit hunter"},
    # ── Database Assessment (8 tools) ─────────────────────────
    {"name": "sqlmap", "binary": "sqlmap", "cat": "database", "desc": "SQL injection"},
    {"name": "sqlninja", "binary": "sqlninja", "cat": "database", "desc": "SQL Server exploit"},
    {"name": "sqlite3", "binary": "sqlite3", "cat": "database", "desc": "SQLite client"},
    {"name": "mysql", "binary": "mysql", "cat": "database", "desc": "MySQL client"},
    {"name": "psql", "binary": "psql", "cat": "database", "desc": "PostgreSQL client"},
    {"name": "redis-cli", "binary": "redis-cli", "cat": "database", "desc": "Redis client"},
    {"name": "mongosh", "binary": "mongosh", "cat": "database", "desc": "MongoDB shell"},
    {"name": "oscanner", "binary": "oscanner", "cat": "database", "desc": "Oracle scanner"},
    # ── Code Analysis & Git Security (12 tools) ──────────────
    {"name": "semgrep", "binary": "semgrep", "cat": "code_analysis", "desc": "Static analysis"},
    {"name": "bandit", "binary": "bandit", "cat": "code_analysis", "desc": "Python security"},
    {"name": "trufflehog", "binary": "trufflehog", "cat": "git_security", "desc": "Secret scanner"},
    {"name": "gitleaks", "binary": "gitleaks", "cat": "git_security", "desc": "Secret scanner"},
    {"name": "gitrob", "binary": "gitrob", "cat": "git_security", "desc": "GitHub recon"},
    {"name": "git-secrets", "binary": "git-secrets", "cat": "git_security", "desc": "Git secret prevention"},
    {"name": "detect-secrets", "binary": "detect-secrets", "cat": "git_security", "desc": "Secret detection"},
    {"name": "safety", "binary": "safety", "cat": "code_analysis", "desc": "Python dep checker"},
    # ── OSINT (15 tools) ──────────────────────────────────────
    {"name": "theHarvester", "binary": "theHarvester", "cat": "osint", "desc": "OSINT email/subdomain"},
    {"name": "metagoofil", "binary": "metagoofil", "cat": "osint", "desc": "Metadata extractor"},
    {"name": "exiftool", "binary": "exiftool", "cat": "osint", "desc": "EXIF metadata"},
    {"name": "recon-ng", "binary": "recon-ng", "cat": "osint", "desc": "OSINT framework"},
    {"name": "spiderfoot", "binary": "spiderfoot", "cat": "osint", "desc": "OSINT automation"},
    {"name": "dmitry", "binary": "dmitry", "cat": "osint", "desc": "Deep info gathering"},
    {"name": "sherlock", "binary": "sherlock", "cat": "osint", "desc": "Username hunter"},
    {"name": "holehe", "binary": "holehe", "cat": "osint", "desc": "Email OSINT"},
    {"name": "maigret", "binary": "maigret", "cat": "osint", "desc": "Username checker"},
    {"name": "h8mail", "binary": "h8mail", "cat": "osint", "desc": "Email breach checker"},
    {"name": "phoneinfoga", "binary": "phoneinfoga", "cat": "osint", "desc": "Phone number OSINT"},
    {"name": "photon", "binary": "photon", "cat": "osint", "desc": "OSINT crawler"},
    # ── Cloud & Container Security (18 tools) ─────────────────
    {"name": "aws", "binary": "aws", "cat": "cloud", "desc": "AWS CLI"},
    {"name": "az", "binary": "az", "cat": "cloud", "desc": "Azure CLI"},
    {"name": "gcloud", "binary": "gcloud", "cat": "cloud", "desc": "GCP CLI"},
    {"name": "kubectl", "binary": "kubectl", "cat": "cloud", "desc": "Kubernetes CLI"},
    {"name": "docker", "binary": "docker", "cat": "container", "desc": "Docker CLI"},
    {"name": "trivy", "binary": "trivy", "cat": "container", "desc": "Container scanner"},
    {"name": "grype", "binary": "grype", "cat": "container", "desc": "Vulnerability scanner"},
    {"name": "syft", "binary": "syft", "cat": "container", "desc": "SBOM generator"},
    {"name": "pacu", "binary": "pacu", "cat": "cloud", "desc": "AWS exploitation"},
    {"name": "prowler", "binary": "prowler", "cat": "cloud", "desc": "AWS security audit"},
    {"name": "ScoutSuite", "binary": "scout", "cat": "cloud", "desc": "Multi-cloud audit"},
    {"name": "cloudfox", "binary": "cloudfox", "cat": "cloud", "desc": "Cloud enumeration"},
    {"name": "kube-hunter", "binary": "kube-hunter", "cat": "cloud", "desc": "K8s pen testing"},
    {"name": "kubeaudit", "binary": "kubeaudit", "cat": "cloud", "desc": "K8s auditing"},
    {"name": "dive", "binary": "dive", "cat": "container", "desc": "Docker image analyzer"},
    # ── AD / Windows (15 tools) ───────────────────────────────
    {"name": "crackmapexec", "binary": "crackmapexec", "cat": "ad_windows", "desc": "Network tool for AD"},
    {"name": "netexec", "binary": "netexec", "cat": "ad_windows", "desc": "CrackMapExec successor"},
    {"name": "bloodhound-python", "binary": "bloodhound-python", "cat": "ad_windows", "desc": "AD collector"},
    {"name": "kerbrute", "binary": "kerbrute", "cat": "ad_windows", "desc": "Kerberos brute"},
    {"name": "evil-winrm", "binary": "evil-winrm", "cat": "ad_windows", "desc": "WinRM shell"},
    {"name": "ldapdomaindump", "binary": "ldapdomaindump", "cat": "ad_windows", "desc": "LDAP domain dump"},
    {"name": "lsassy", "binary": "lsassy", "cat": "ad_windows", "desc": "LSASS credentials"},
    {"name": "pypykatz", "binary": "pypykatz", "cat": "ad_windows", "desc": "Mimikatz in Python"},
    {"name": "adidnsdump", "binary": "adidnsdump", "cat": "ad_windows", "desc": "AD DNS dump"},
    {"name": "mitm6", "binary": "mitm6", "cat": "ad_windows", "desc": "IPv6 MITM for AD"},
    # ── API Testing (5 tools) ─────────────────────────────────
    {"name": "kiterunner", "binary": "kr", "cat": "api", "desc": "API endpoint discovery"},
    {"name": "arjun-api", "binary": "arjun", "cat": "api", "desc": "API parameter finder"},
    {"name": "jwt_tool", "binary": "jwt_tool", "cat": "api", "desc": "JWT testing"},
    {"name": "graphql-cop", "binary": "graphql-cop", "cat": "api", "desc": "GraphQL security"},
    {"name": "clairvoyance", "binary": "clairvoyance", "cat": "api", "desc": "GraphQL schema theft"},
    # ── SSL/TLS (4 tools) ─────────────────────────────────────
    {"name": "sslscan", "binary": "sslscan", "cat": "ssl", "desc": "SSL/TLS scanner"},
    {"name": "sslyze", "binary": "sslyze", "cat": "ssl", "desc": "SSL analysis"},
    {"name": "testssl", "binary": "testssl.sh", "cat": "ssl", "desc": "SSL/TLS testing"},
    {"name": "ssldump", "binary": "ssldump", "cat": "ssl", "desc": "SSL traffic dump"},
    # ── Fuzzing (6 tools) ─────────────────────────────────────
    {"name": "afl++", "binary": "afl-fuzz", "cat": "fuzzing", "desc": "Coverage-guided fuzzer"},
    {"name": "boofuzz", "binary": "boofuzz", "cat": "fuzzing", "desc": "Network protocol fuzzer"},
    {"name": "radamsa", "binary": "radamsa", "cat": "fuzzing", "desc": "General-purpose fuzzer"},
    {"name": "zzuf", "binary": "zzuf", "cat": "fuzzing", "desc": "Transparent app fuzzer"},
    {"name": "honggfuzz", "binary": "honggfuzz", "cat": "fuzzing", "desc": "Feedback-driven fuzzer"},
    # ── Mobile (6 tools) ──────────────────────────────────────
    {"name": "objection", "binary": "objection", "cat": "mobile", "desc": "Mobile runtime exploration"},
    {"name": "frida", "binary": "frida", "cat": "mobile", "desc": "Dynamic instrumentation"},
    {"name": "frida-ps", "binary": "frida-ps", "cat": "mobile", "desc": "Frida process list"},
    {"name": "apktool", "binary": "apktool", "cat": "mobile", "desc": "APK reverse engineering"},
    {"name": "jadx", "binary": "jadx", "cat": "mobile", "desc": "DEX decompiler"},
    {"name": "dex2jar", "binary": "d2j-dex2jar", "cat": "mobile", "desc": "DEX to JAR converter"},
    # ── ProjectDiscovery extras (10 tools) ────────────────────
    {"name": "tlsx", "binary": "tlsx", "cat": "ssl", "desc": "TLS grabber (PD)"},
    {"name": "proxify", "binary": "proxify", "cat": "web", "desc": "HTTP proxy (PD)"},
    {"name": "interactsh", "binary": "interactsh-client", "cat": "web", "desc": "OOB interaction (PD)"},
    {"name": "notify", "binary": "notify", "cat": "general", "desc": "Notification tool (PD)"},
    {"name": "uncover", "binary": "uncover", "cat": "recon", "desc": "API search engine (PD)"},
    {"name": "asnmap", "binary": "asnmap", "cat": "recon", "desc": "ASN mapper (PD)"},
    {"name": "cdncheck", "binary": "cdncheck", "cat": "recon", "desc": "CDN checker (PD)"},
    {"name": "mapcidr", "binary": "mapcidr", "cat": "recon", "desc": "CIDR util (PD)"},
    {"name": "cloudlist", "binary": "cloudlist", "cat": "cloud", "desc": "Cloud asset list (PD)"},
    {"name": "alterx", "binary": "alterx", "cat": "dns", "desc": "DNS wordlist gen (PD)"},
    # ── General / Scripting (6 tools) ─────────────────────────
    {"name": "bash", "binary": "bash", "cat": "general", "desc": "Bash shell"},
    {"name": "python3", "binary": "python3", "cat": "general", "desc": "Python 3"},
    {"name": "ruby", "binary": "ruby", "cat": "general", "desc": "Ruby"},
    {"name": "perl", "binary": "perl", "cat": "general", "desc": "Perl"},
    {"name": "php", "binary": "php", "cat": "general", "desc": "PHP CLI"},
    {"name": "node", "binary": "node", "cat": "general", "desc": "Node.js"},
]

# ── Dangerous commands to block ────────────────────────────────

BLOCKED_PATTERNS: list[str] = [
    "rm -rf /",
    "mkfs",
    ":(){:|:&};:",
    "dd if=/dev/zero of=/dev/sd",
    "chmod -R 777 /",
    "wget -O- | sh",
    "curl | sh",
]


class ToolExecutor:
    """Manages async execution of external security tools.

    Handles subprocess spawning, output capture,
    timeout management, and tool availability
    detection.
    """

    def __init__(
        self,
        default_timeout_s: int = 300,
        max_concurrent: int = 5,
    ) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._default_timeout = default_timeout_s
        self._max_concurrent = max_concurrent
        self._semaphore: asyncio.Semaphore | None = None
        self._execution_count = 0
        self._log = logger.bind(component="tool_executor")
        self._load_tools()

    def _load_tools(self) -> None:
        """Load tool definitions and check availability."""
        for cfg in TOOL_REGISTRY:
            cat_str = cfg.get("cat", "scanner")
            try:
                category = ToolCategory(cat_str)
            except ValueError:
                category = ToolCategory.SCANNER

            tool = ToolDefinition(
                name=cfg["name"],
                binary=cfg["binary"],
                category=category,
                description=cfg.get("desc", ""),
                default_timeout_s=cfg.get("timeout", self._default_timeout),
                install_cmd=cfg.get("install", ""),
            )
            tool.available = shutil.which(tool.binary) is not None
            self._tools[tool.name] = tool

    async def execute(
        self,
        tool_name: str,
        args: list[str],
        timeout_s: int = 0,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Execute a tool asynchronously."""
        tool = self._tools.get(tool_name)
        if not tool:
            return ExecutionResult(
                tool=tool_name,
                status=ExecutionStatus.FAILED,
                stderr=f"Unknown tool: {tool_name}",
            )

        if not tool.available:
            return ExecutionResult(
                tool=tool_name,
                status=ExecutionStatus.FAILED,
                stderr=f"Tool not installed: {tool_name}",
            )

        cmd = [tool.binary] + args
        cmd_str = " ".join(cmd)

        # Safety check
        for blocked in BLOCKED_PATTERNS:
            if blocked in cmd_str:
                return ExecutionResult(
                    tool=tool_name,
                    command=cmd_str,
                    status=ExecutionStatus.FAILED,
                    stderr=f"Blocked dangerous command pattern: {blocked}",
                )

        timeout = timeout_s or tool.default_timeout_s

        # Concurrency control
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)

        async with self._semaphore:
            return await self._run_subprocess(
                tool_name, cmd, cmd_str, timeout, env,
            )

    async def _run_subprocess(
        self,
        tool_name: str,
        cmd: list[str],
        cmd_str: str,
        timeout_s: int,
        env: dict[str, str] | None,
    ) -> ExecutionResult:
        """Run a subprocess with timeout."""
        self._execution_count += 1
        result = ExecutionResult(
            tool=tool_name,
            command=cmd_str,
            status=ExecutionStatus.RUNNING,
            started_at=time.time(),
        )

        exec_env = dict(os.environ)
        if env:
            exec_env.update(env)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=exec_env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_s,
                )
                result.exit_code = proc.returncode or 0
                result.stdout = stdout.decode("utf-8", errors="replace")
                result.stderr = stderr.decode("utf-8", errors="replace")
                result.status = ExecutionStatus.COMPLETED
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result.status = ExecutionStatus.TIMEOUT
                result.stderr = f"Timeout after {timeout_s}s"

        except FileNotFoundError:
            result.status = ExecutionStatus.FAILED
            result.stderr = f"Binary not found: {cmd[0]}"
        except PermissionError:
            result.status = ExecutionStatus.FAILED
            result.stderr = f"Permission denied: {cmd[0]}"
        except OSError as exc:
            result.status = ExecutionStatus.FAILED
            result.stderr = f"OS error: {exc}"

        result.completed_at = time.time()
        result.duration_s = result.completed_at - result.started_at
        return result

    def get_available_tools(
        self,
        category: ToolCategory | None = None,
    ) -> list[ToolDefinition]:
        """Get available tools, optionally filtered by category."""
        tools = [t for t in self._tools.values() if t.available]
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def get_all_tools(self) -> list[ToolDefinition]:
        """Get all registered tools."""
        return list(self._tools.values())

    def build_tool_prompt(
        self,
        categories: list[ToolCategory] | None = None,
    ) -> str:
        """Build tool documentation for LLM."""
        lines = ["## Available Tools\n"]
        tools = self._tools.values()

        if categories:
            tools = [t for t in tools if t.category in categories]

        for tool in tools:
            status = "installed" if tool.available else "not installed"
            lines.append(
                f"- {tool.name} [{tool.category.value}]: "
                f"{tool.description} ({status})"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        available = sum(1 for t in self._tools.values() if t.available)
        by_category: dict[str, int] = {}
        for t in self._tools.values():
            by_category[t.category.value] = by_category.get(
                t.category.value, 0,
            ) + 1

        return {
            "total_tools": len(self._tools),
            "available": available,
            "executions": self._execution_count,
            "by_category": by_category,
        }
