"""Tool registry — manages 200+ security tools with auto-detection, install, and hot-add."""

from __future__ import annotations

from typing import Any

import structlog

from recursec.core.models import ToolCategory, ToolResult
from recursec.tools.base import BaseTool, ShellTool

logger = structlog.get_logger()


# ═══════════════════════════════════════════════════════
# TOOL DEFINITIONS — 200+ security tools
# Each entry: (name, binary, category, description, install_cmd)
# ═══════════════════════════════════════════════════════

TOOL_DEFINITIONS: list[tuple[str, str, ToolCategory, str, str]] = [
    # ── RECON ──────────────────────────────────────────
    ("nmap", "nmap", ToolCategory.RECON, "Network port scanner and service detection", "apt install -y nmap"),
    ("masscan", "masscan", ToolCategory.RECON, "Fastest port scanner (10M packets/sec)", "apt install -y masscan"),
    ("rustscan", "rustscan", ToolCategory.RECON, "Fast port scanner written in Rust", "cargo install rustscan"),
    ("zmap", "zmap", ToolCategory.RECON, "Internet-wide network scanner", "apt install -y zmap"),
    ("unicornscan", "unicornscan", ToolCategory.RECON, "Asynchronous network scanner", "apt install -y unicornscan"),
    ("hping3", "hping3", ToolCategory.RECON, "TCP/IP packet assembler/analyzer", "apt install -y hping3"),
    ("arping", "arping", ToolCategory.RECON, "ARP-level ping utility", "apt install -y arping"),
    ("fping", "fping", ToolCategory.RECON, "Fast ping sweep tool", "apt install -y fping"),
    ("netdiscover", "netdiscover", ToolCategory.RECON, "Active/passive ARP recon", "apt install -y netdiscover"),
    ("nbtscan", "nbtscan", ToolCategory.RECON, "NetBIOS name scanner", "apt install -y nbtscan"),
    ("enum4linux", "enum4linux", ToolCategory.RECON, "Windows/Samba enumeration", "apt install -y enum4linux"),
    ("dnsrecon", "dnsrecon", ToolCategory.RECON, "DNS enumeration tool", "apt install -y dnsrecon"),
    ("dnsenum", "dnsenum", ToolCategory.RECON, "DNS enumeration and zone transfer", "apt install -y dnsenum"),
    ("fierce", "fierce", ToolCategory.RECON, "DNS reconnaissance tool", "pip install fierce"),
    ("theHarvester", "theHarvester", ToolCategory.RECON, "Email, subdomain, and name harvester", "apt install -y theharvester"),
    ("subfinder", "subfinder", ToolCategory.RECON, "Fast subdomain discovery", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("amass", "amass", ToolCategory.RECON, "In-depth attack surface mapping", "go install github.com/owasp-amass/amass/v4/...@master"),
    ("httpx", "httpx", ToolCategory.RECON, "Fast HTTP probing tool", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("whatweb", "whatweb", ToolCategory.RECON, "Web technology fingerprinting", "apt install -y whatweb"),
    ("wafw00f", "wafw00f", ToolCategory.RECON, "WAF detection tool", "pip install wafw00f"),
    ("sslscan", "sslscan", ToolCategory.RECON, "SSL/TLS configuration scanner", "apt install -y sslscan"),
    ("sslyze", "sslyze", ToolCategory.RECON, "SSL/TLS configuration analyzer", "pip install sslyze"),
    ("testssl", "testssl.sh", ToolCategory.RECON, "SSL/TLS testing tool", "apt install -y testssl.sh"),
    ("traceroute", "traceroute", ToolCategory.RECON, "Network path tracing", "apt install -y traceroute"),
    ("whois", "whois", ToolCategory.RECON, "WHOIS lookup", "apt install -y whois"),
    ("dig", "dig", ToolCategory.RECON, "DNS lookup utility", "apt install -y dnsutils"),
    ("host", "host", ToolCategory.RECON, "DNS lookup utility", "apt install -y dnsutils"),
    ("nslookup", "nslookup", ToolCategory.RECON, "DNS query tool", "apt install -y dnsutils"),
    ("snmpwalk", "snmpwalk", ToolCategory.RECON, "SNMP device walker", "apt install -y snmp"),
    ("onesixtyone", "onesixtyone", ToolCategory.RECON, "Fast SNMP scanner", "apt install -y onesixtyone"),

    # ── VULNERABILITY SCANNING ─────────────────────────
    ("nuclei", "nuclei", ToolCategory.VULN_SCAN, "Template-based vulnerability scanner (ProjectDiscovery)", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("nikto", "nikto", ToolCategory.VULN_SCAN, "Web server vulnerability scanner", "apt install -y nikto"),
    ("openvas", "openvas", ToolCategory.VULN_SCAN, "Full vulnerability scanner (Greenbone)", "apt install -y openvas"),
    ("nessus", "nessusd", ToolCategory.VULN_SCAN, "Professional vulnerability scanner", "# Download from tenable.com"),
    ("wpscan", "wpscan", ToolCategory.VULN_SCAN, "WordPress vulnerability scanner", "gem install wpscan"),
    ("joomscan", "joomscan", ToolCategory.VULN_SCAN, "Joomla vulnerability scanner", "apt install -y joomscan"),
    ("droopescan", "droopescan", ToolCategory.VULN_SCAN, "CMS vulnerability scanner", "pip install droopescan"),
    ("cmsmap", "cmsmap", ToolCategory.VULN_SCAN, "CMS vulnerability scanner", "pip install cmsmap"),
    ("vulscan", "vulscan", ToolCategory.VULN_SCAN, "Nmap NSE vulnerability scanner", "git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan"),
    ("vulners", "vulners", ToolCategory.VULN_SCAN, "Vulnerability database search", "pip install vulners"),
    ("retire.js", "retire", ToolCategory.VULN_SCAN, "JavaScript library vulnerability scanner", "npm install -g retire"),
    ("snyk", "snyk", ToolCategory.VULN_SCAN, "Dependency vulnerability scanner", "npm install -g snyk"),
    ("trivy", "trivy", ToolCategory.VULN_SCAN, "Container/IaC vulnerability scanner", "apt install -y trivy"),
    ("grype", "grype", ToolCategory.VULN_SCAN, "Container image vulnerability scanner", "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"),
    ("lynis", "lynis", ToolCategory.VULN_SCAN, "Security auditing tool for Unix", "apt install -y lynis"),
    ("linux-exploit-suggester", "les.sh", ToolCategory.VULN_SCAN, "Linux kernel exploit suggester", "git clone https://github.com/mzet-/linux-exploit-suggester"),
    ("windows-exploit-suggester", "wes.py", ToolCategory.VULN_SCAN, "Windows exploit suggester", "pip install wesng"),

    # ── WEB APPLICATION TESTING ────────────────────────
    ("sqlmap", "sqlmap", ToolCategory.WEB, "Automatic SQL injection and database takeover", "apt install -y sqlmap"),
    ("xsstrike", "xsstrike", ToolCategory.WEB, "Advanced XSS detection suite", "pip install xsstrike"),
    ("dalfox", "dalfox", ToolCategory.WEB, "Fast XSS scanner", "go install github.com/hahwul/dalfox/v2@latest"),
    ("commix", "commix", ToolCategory.WEB, "Command injection exploitation", "apt install -y commix"),
    ("tplmap", "tplmap", ToolCategory.WEB, "Server-Side Template Injection", "git clone https://github.com/epinna/tplmap"),
    ("ssrfmap", "ssrfmap", ToolCategory.WEB, "SSRF exploitation framework", "pip install ssrfmap"),
    ("xxeinjector", "xxeinjector", ToolCategory.WEB, "XXE injection tool", "git clone https://github.com/enjoiz/XXEinjector"),
    ("nosqlmap", "nosqlmap", ToolCategory.WEB, "NoSQL injection tool", "pip install nosqlmap"),
    ("gobuster", "gobuster", ToolCategory.WEB, "Directory/file/DNS brute-forcer", "go install github.com/OJ/gobuster/v3@latest"),
    ("ffuf", "ffuf", ToolCategory.WEB, "Fast web fuzzer", "go install github.com/ffuf/ffuf/v2@latest"),
    ("feroxbuster", "feroxbuster", ToolCategory.WEB, "Fast content discovery (Rust)", "apt install -y feroxbuster"),
    ("dirsearch", "dirsearch", ToolCategory.WEB, "Web path scanner", "pip install dirsearch"),
    ("dirb", "dirb", ToolCategory.WEB, "Web content scanner", "apt install -y dirb"),
    ("wfuzz", "wfuzz", ToolCategory.WEB, "Web application fuzzer", "pip install wfuzz"),
    ("arjun", "arjun", ToolCategory.WEB, "HTTP parameter discovery", "pip install arjun"),
    ("paramspider", "paramspider", ToolCategory.WEB, "Parameter mining from web archives", "pip install paramspider"),
    ("katana", "katana", ToolCategory.WEB, "Fast web crawler (ProjectDiscovery)", "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("hakrawler", "hakrawler", ToolCategory.WEB, "Web crawler for gathering URLs", "go install github.com/hakluke/hakrawler@latest"),
    ("gospider", "gospider", ToolCategory.WEB, "Fast web spider written in Go", "go install github.com/jaeles-project/gospider@latest"),
    ("gau", "gau", ToolCategory.WEB, "Get All URLs from web archives", "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ("waybackurls", "waybackurls", ToolCategory.WEB, "Fetch URLs from Wayback Machine", "go install github.com/tomnomnom/waybackurls@latest"),
    ("cors-scanner", "cors-scanner", ToolCategory.WEB, "CORS misconfiguration scanner", "pip install cors-scanner"),
    ("jwt-tool", "jwt_tool", ToolCategory.WEB, "JWT token manipulation toolkit", "pip install jwt-tool"),
    ("graphqlmap", "graphqlmap", ToolCategory.WEB, "GraphQL endpoint exploitation", "pip install graphqlmap"),
    ("postman", "postman", ToolCategory.WEB, "API testing tool", "snap install postman"),

    # ── EXPLOITATION ───────────────────────────────────
    ("metasploit", "msfconsole", ToolCategory.EXPLOIT, "Penetration testing framework", "apt install -y metasploit-framework"),
    ("searchsploit", "searchsploit", ToolCategory.EXPLOIT, "Exploit database search tool", "apt install -y exploitdb"),
    ("msfvenom", "msfvenom", ToolCategory.EXPLOIT, "Payload generator", "apt install -y metasploit-framework"),
    ("beef", "beef-xss", ToolCategory.EXPLOIT, "Browser Exploitation Framework", "apt install -y beef-xss"),
    ("routersploit", "rsf", ToolCategory.EXPLOIT, "Router exploitation framework", "pip install routersploit"),
    ("pwntools", "pwn", ToolCategory.EXPLOIT, "CTF/exploit development library", "pip install pwntools"),
    ("ropper", "ropper", ToolCategory.EXPLOIT, "ROP gadget finder", "pip install ropper"),
    ("one_gadget", "one_gadget", ToolCategory.EXPLOIT, "Finds one-shot RCE gadgets in libc", "gem install one_gadget"),
    ("checksec", "checksec", ToolCategory.EXPLOIT, "Binary security property checker", "apt install -y checksec"),

    # ── NETWORK ────────────────────────────────────────
    ("wireshark", "tshark", ToolCategory.NETWORK, "Network protocol analyzer (CLI)", "apt install -y tshark"),
    ("tcpdump", "tcpdump", ToolCategory.NETWORK, "Packet capture tool", "apt install -y tcpdump"),
    ("netcat", "nc", ToolCategory.NETWORK, "TCP/UDP Swiss Army knife", "apt install -y netcat-openbsd"),
    ("socat", "socat", ToolCategory.NETWORK, "Multipurpose relay tool", "apt install -y socat"),
    ("responder", "responder", ToolCategory.NETWORK, "LLMNR/NBT-NS/mDNS poisoner", "apt install -y responder"),
    ("bettercap", "bettercap", ToolCategory.NETWORK, "Network attack and monitoring framework", "apt install -y bettercap"),
    ("ettercap", "ettercap", ToolCategory.NETWORK, "Man-in-the-middle attack suite", "apt install -y ettercap-text-only"),
    ("arpspoof", "arpspoof", ToolCategory.NETWORK, "ARP spoofing tool", "apt install -y dsniff"),
    ("mitmproxy", "mitmproxy", ToolCategory.NETWORK, "Interactive TLS-capable intercepting proxy", "pip install mitmproxy"),
    ("proxychains", "proxychains4", ToolCategory.NETWORK, "Proxy chaining tool", "apt install -y proxychains4"),
    ("chisel", "chisel", ToolCategory.NETWORK, "Fast TCP/UDP tunnel over HTTP", "go install github.com/jpillora/chisel@latest"),
    ("sshuttle", "sshuttle", ToolCategory.NETWORK, "Transparent proxy VPN over SSH", "apt install -y sshuttle"),
    ("ngrok", "ngrok", ToolCategory.NETWORK, "Secure tunneling", "snap install ngrok"),

    # ── POST EXPLOITATION ──────────────────────────────
    ("linpeas", "linpeas.sh", ToolCategory.POST_EXPLOIT, "Linux privilege escalation awesome script", "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /usr/local/bin/linpeas.sh"),
    ("winpeas", "winpeas.exe", ToolCategory.POST_EXPLOIT, "Windows privilege escalation awesome script", "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe -o /usr/local/bin/winpeas.exe"),
    ("pspy", "pspy", ToolCategory.POST_EXPLOIT, "Monitor Linux processes without root", "curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /usr/local/bin/pspy"),
    ("bloodhound", "bloodhound", ToolCategory.POST_EXPLOIT, "Active Directory attack path mapper", "apt install -y bloodhound"),
    ("sharphound", "sharphound", ToolCategory.POST_EXPLOIT, "BloodHound data collector", "# Download from GitHub releases"),
    ("mimikatz", "mimikatz", ToolCategory.POST_EXPLOIT, "Windows credential extraction", "# Download from GitHub releases"),
    ("lazagne", "lazagne", ToolCategory.POST_EXPLOIT, "Credentials recovery tool", "pip install lazagne"),
    ("crackmapexec", "crackmapexec", ToolCategory.POST_EXPLOIT, "Network penetration testing tool", "pip install crackmapexec"),
    ("netexec", "nxc", ToolCategory.POST_EXPLOIT, "Network execution tool (CrackMapExec successor)", "pip install netexec"),
    ("evil-winrm", "evil-winrm", ToolCategory.POST_EXPLOIT, "WinRM shell for pentesting", "gem install evil-winrm"),
    ("impacket", "impacket-smbexec", ToolCategory.POST_EXPLOIT, "Network protocol toolkit", "pip install impacket"),
    ("empire", "empire", ToolCategory.POST_EXPLOIT, "Post-exploitation C2 framework", "git clone https://github.com/BC-SECURITY/Empire"),
    ("sliver", "sliver", ToolCategory.POST_EXPLOIT, "Adversary emulation/C2 framework", "# Download from GitHub releases"),
    ("covenant", "covenant", ToolCategory.POST_EXPLOIT, ".NET command and control framework", "# Download from GitHub releases"),

    # ── CODE ANALYSIS ──────────────────────────────────
    ("semgrep", "semgrep", ToolCategory.CODE_ANALYSIS, "Static analysis engine (SAST)", "pip install semgrep"),
    ("codeql", "codeql", ToolCategory.CODE_ANALYSIS, "Semantic code analysis engine (GitHub)", "# Download from GitHub releases"),
    ("bandit", "bandit", ToolCategory.CODE_ANALYSIS, "Python security linter", "pip install bandit"),
    ("gosec", "gosec", ToolCategory.CODE_ANALYSIS, "Go security checker", "go install github.com/securego/gosec/v2/cmd/gosec@latest"),
    ("brakeman", "brakeman", ToolCategory.CODE_ANALYSIS, "Ruby on Rails security scanner", "gem install brakeman"),
    ("safety", "safety", ToolCategory.CODE_ANALYSIS, "Python dependency vulnerability checker", "pip install safety"),
    ("npm-audit", "npm", ToolCategory.CODE_ANALYSIS, "Node.js dependency audit", "# Built into npm"),
    ("flawfinder", "flawfinder", ToolCategory.CODE_ANALYSIS, "C/C++ source code security scanner", "pip install flawfinder"),
    ("phpstan", "phpstan", ToolCategory.CODE_ANALYSIS, "PHP static analysis tool", "composer require --dev phpstan/phpstan"),
    ("pyre", "pyre", ToolCategory.CODE_ANALYSIS, "Python type checker (Meta)", "pip install pyre-check"),
    ("graudit", "graudit", ToolCategory.CODE_ANALYSIS, "Grep-based source code auditing", "git clone https://github.com/wireghoul/graudit"),
    ("insider", "insider", ToolCategory.CODE_ANALYSIS, "SAST for multiple languages", "# Download from GitHub releases"),
    ("horusec", "horusec", ToolCategory.CODE_ANALYSIS, "SAST tool for multiple languages", "curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash"),
    ("sonarqube", "sonar-scanner", ToolCategory.CODE_ANALYSIS, "Code quality and security platform", "# Download from sonarqube.org"),
    ("opengrep", "opengrep", ToolCategory.CODE_ANALYSIS, "Open-source Semgrep fork", "pip install opengrep"),
    ("ast-grep", "ast-grep", ToolCategory.CODE_ANALYSIS, "AST-based code search tool", "npm install -g @ast-grep/cli"),

    # ── CRYPTO ─────────────────────────────────────────
    ("hashcat", "hashcat", ToolCategory.CRYPTO, "Advanced password recovery tool", "apt install -y hashcat"),
    ("john", "john", ToolCategory.CRYPTO, "John the Ripper password cracker", "apt install -y john"),
    ("hydra", "hydra", ToolCategory.CRYPTO, "Fast network logon cracker", "apt install -y hydra"),
    ("medusa", "medusa", ToolCategory.CRYPTO, "Parallel password cracker", "apt install -y medusa"),
    ("ncrack", "ncrack", ToolCategory.CRYPTO, "High-speed network authentication cracker", "apt install -y ncrack"),
    ("ophcrack", "ophcrack", ToolCategory.CRYPTO, "Windows password cracker via rainbow tables", "apt install -y ophcrack"),
    ("cewl", "cewl", ToolCategory.CRYPTO, "Custom wordlist generator from websites", "apt install -y cewl"),
    ("crunch", "crunch", ToolCategory.CRYPTO, "Wordlist generator", "apt install -y crunch"),
    ("rsatool", "rsatool", ToolCategory.CRYPTO, "RSA key manipulation", "pip install rsatool"),
    ("hashid", "hashid", ToolCategory.CRYPTO, "Hash type identifier", "pip install hashid"),
    ("hash-identifier", "hash-identifier", ToolCategory.CRYPTO, "Hash identification tool", "apt install -y hash-identifier"),

    # ── OSINT ──────────────────────────────────────────
    ("shodan", "shodan", ToolCategory.OSINT, "Shodan CLI (IoT/server search)", "pip install shodan"),
    ("censys", "censys", ToolCategory.OSINT, "Censys search engine CLI", "pip install censys"),
    ("recon-ng", "recon-ng", ToolCategory.OSINT, "Web reconnaissance framework", "apt install -y recon-ng"),
    ("maltego", "maltego", ToolCategory.OSINT, "OSINT and link analysis", "# Download from maltego.com"),
    ("spiderfoot", "spiderfoot", ToolCategory.OSINT, "OSINT automation tool", "pip install spiderfoot"),
    ("holehe", "holehe", ToolCategory.OSINT, "Email to social media account finder", "pip install holehe"),
    ("sherlock", "sherlock", ToolCategory.OSINT, "Social media username hunter", "pip install sherlock-project"),
    ("photon", "photon", ToolCategory.OSINT, "OSINT web crawler", "pip install photon"),
    ("ghunt", "ghunt", ToolCategory.OSINT, "Google account OSINT", "pip install ghunt"),
    ("phoneinfoga", "phoneinfoga", ToolCategory.OSINT, "Phone number OSINT", "# Download from GitHub releases"),
    ("twint", "twint", ToolCategory.OSINT, "Twitter intelligence tool", "pip install twint"),

    # ── FUZZING ────────────────────────────────────────
    ("afl", "afl-fuzz", ToolCategory.FUZZING, "American Fuzzy Lop fuzzer", "apt install -y afl++"),
    ("libfuzzer", "libfuzzer", ToolCategory.FUZZING, "In-process coverage-guided fuzzer", "# Part of LLVM/Clang"),
    ("honggfuzz", "honggfuzz", ToolCategory.FUZZING, "Security-oriented fuzzer", "apt install -y honggfuzz"),
    ("boofuzz", "boofuzz", ToolCategory.FUZZING, "Network protocol fuzzer", "pip install boofuzz"),
    ("radamsa", "radamsa", ToolCategory.FUZZING, "General-purpose test case generator", "apt install -y radamsa"),
    ("zzuf", "zzuf", ToolCategory.FUZZING, "Transparent fuzzing tool", "apt install -y zzuf"),
    ("schemathesis", "schemathesis", ToolCategory.FUZZING, "API fuzzer (OpenAPI/GraphQL)", "pip install schemathesis"),
    ("restler", "restler", ToolCategory.FUZZING, "REST API fuzzer (Microsoft)", "# Download from GitHub releases"),

    # ── WIRELESS ───────────────────────────────────────
    ("aircrack-ng", "aircrack-ng", ToolCategory.WIRELESS, "WiFi security suite", "apt install -y aircrack-ng"),
    ("kismet", "kismet", ToolCategory.WIRELESS, "Wireless network detector/sniffer", "apt install -y kismet"),
    ("wifite", "wifite", ToolCategory.WIRELESS, "Automated wireless attack tool", "apt install -y wifite"),
    ("reaver", "reaver", ToolCategory.WIRELESS, "WPS brute force tool", "apt install -y reaver"),
    ("pixiewps", "pixiewps", ToolCategory.WIRELESS, "WPS offline brute force tool", "apt install -y pixiewps"),
    ("fluxion", "fluxion", ToolCategory.WIRELESS, "Wireless social engineering tool", "git clone https://github.com/FluxionNetwork/fluxion"),
    ("bully", "bully", ToolCategory.WIRELESS, "WPS brute force attack tool", "apt install -y bully"),
    ("hostapd-mana", "hostapd-mana", ToolCategory.WIRELESS, "Rogue access point tool", "apt install -y hostapd-mana"),
    ("eaphammer", "eaphammer", ToolCategory.WIRELESS, "EAP attack tool", "git clone https://github.com/s0lst1c3/eaphammer"),
    ("hcxtools", "hcxdumptool", ToolCategory.WIRELESS, "WiFi capture and conversion tools", "apt install -y hcxtools"),

    # ── CLOUD ──────────────────────────────────────────
    ("prowler", "prowler", ToolCategory.CLOUD, "AWS/Azure/GCP security assessment", "pip install prowler"),
    ("scoutsuite", "scout", ToolCategory.CLOUD, "Multi-cloud security auditing", "pip install scoutsuite"),
    ("pacu", "pacu", ToolCategory.CLOUD, "AWS exploitation framework", "pip install pacu"),
    ("cloudsploit", "cloudsploit", ToolCategory.CLOUD, "Cloud security posture scanner", "npm install -g cloudsploit"),
    ("steampipe", "steampipe", ToolCategory.CLOUD, "Cloud infrastructure querying", "# Download from steampipe.io"),
    ("enumerate-iam", "enumerate-iam", ToolCategory.CLOUD, "AWS IAM permission enumeration", "pip install enumerate-iam"),
    ("s3scanner", "s3scanner", ToolCategory.CLOUD, "AWS S3 bucket scanner", "pip install s3scanner"),
    ("gcp-scanner", "gcp-scanner", ToolCategory.CLOUD, "GCP resource scanner", "pip install gcp-scanner"),
    ("azurehound", "azurehound", ToolCategory.CLOUD, "Azure environment analysis", "# Download from GitHub releases"),
    ("cloudfox", "cloudfox", ToolCategory.CLOUD, "Cloud penetration testing tool", "go install github.com/BishopFox/cloudfox@latest"),

    # ── FORENSICS ──────────────────────────────────────
    ("volatility", "vol.py", ToolCategory.FORENSICS, "Memory forensics framework", "pip install volatility3"),
    ("autopsy", "autopsy", ToolCategory.FORENSICS, "Digital forensics platform", "apt install -y autopsy"),
    ("sleuthkit", "fls", ToolCategory.FORENSICS, "File system forensic tools", "apt install -y sleuthkit"),
    ("foremost", "foremost", ToolCategory.FORENSICS, "File carving tool", "apt install -y foremost"),
    ("binwalk", "binwalk", ToolCategory.FORENSICS, "Firmware analysis tool", "pip install binwalk"),
    ("exiftool", "exiftool", ToolCategory.FORENSICS, "Metadata extraction tool", "apt install -y libimage-exiftool-perl"),
    ("pdf-parser", "pdf-parser", ToolCategory.FORENSICS, "PDF file analysis", "pip install pdf-parser"),
    ("yara", "yara", ToolCategory.FORENSICS, "Malware pattern matching", "apt install -y yara"),
    ("strings", "strings", ToolCategory.FORENSICS, "Extract printable strings from files", "apt install -y binutils"),
    ("radare2", "r2", ToolCategory.FORENSICS, "Reverse engineering framework", "apt install -y radare2"),
    ("ghidra", "ghidra", ToolCategory.FORENSICS, "NSA reverse engineering tool", "# Download from ghidra-sre.org"),
    ("strace", "strace", ToolCategory.FORENSICS, "System call tracer", "apt install -y strace"),
    ("ltrace", "ltrace", ToolCategory.FORENSICS, "Library call tracer", "apt install -y ltrace"),
    ("gdb", "gdb", ToolCategory.FORENSICS, "GNU debugger", "apt install -y gdb"),

    # ── REPORTING ──────────────────────────────────────
    ("pandoc", "pandoc", ToolCategory.REPORTING, "Universal document converter", "apt install -y pandoc"),
    ("wkhtmltopdf", "wkhtmltopdf", ToolCategory.REPORTING, "HTML to PDF converter", "apt install -y wkhtmltopdf"),
    ("dradis", "dradis", ToolCategory.REPORTING, "Reporting and collaboration platform", "gem install dradis"),
    ("faraday", "faraday", ToolCategory.REPORTING, "Collaborative pentest platform", "pip install faraday"),

    # ── MISC UTILITIES ─────────────────────────────────
    ("curl", "curl", ToolCategory.MISC, "HTTP client", "apt install -y curl"),
    ("wget", "wget", ToolCategory.MISC, "File downloader", "apt install -y wget"),
    ("git", "git", ToolCategory.MISC, "Version control system", "apt install -y git"),
    ("python3", "python3", ToolCategory.MISC, "Python interpreter", "apt install -y python3"),
    ("pip", "pip", ToolCategory.MISC, "Python package manager", "apt install -y python3-pip"),
    ("go", "go", ToolCategory.MISC, "Go programming language", "apt install -y golang"),
    ("node", "node", ToolCategory.MISC, "Node.js runtime", "apt install -y nodejs"),
    ("ruby", "ruby", ToolCategory.MISC, "Ruby runtime", "apt install -y ruby"),
    ("jq", "jq", ToolCategory.MISC, "JSON processor", "apt install -y jq"),
    ("xmllint", "xmllint", ToolCategory.MISC, "XML parser", "apt install -y libxml2-utils"),
    ("xsltproc", "xsltproc", ToolCategory.MISC, "XSLT processor", "apt install -y xsltproc"),
    ("awk", "awk", ToolCategory.MISC, "Text processing", "apt install -y gawk"),
    ("sed", "sed", ToolCategory.MISC, "Stream editor", "# Built-in"),
    ("grep", "grep", ToolCategory.MISC, "Pattern matching", "# Built-in"),
    ("base64", "base64", ToolCategory.MISC, "Base64 encoding/decoding", "# Built-in"),
    ("openssl", "openssl", ToolCategory.MISC, "SSL/TLS toolkit", "apt install -y openssl"),
    ("gpg", "gpg", ToolCategory.MISC, "GnuPG encryption", "apt install -y gnupg"),
    ("docker", "docker", ToolCategory.MISC, "Container runtime", "apt install -y docker.io"),
    ("proxychains", "proxychains4", ToolCategory.MISC, "Proxy chaining", "apt install -y proxychains4"),
    ("tor", "tor", ToolCategory.MISC, "Anonymous network", "apt install -y tor"),
    ("screen", "screen", ToolCategory.MISC, "Terminal multiplexer", "apt install -y screen"),
    ("tmux", "tmux", ToolCategory.MISC, "Terminal multiplexer", "apt install -y tmux"),
]


class DynamicTool(BaseTool):
    """A dynamically created tool from registry definitions."""

    def __init__(self, name: str, binary: str, category: ToolCategory, description: str, install_cmd: str, **kwargs: Any):
        super().__init__(**kwargs)
        self.name = name
        self.binary_name = binary
        self.category = category
        self.description = description
        self.install_command = install_cmd

    def build_command(self, **kwargs) -> str:
        args = kwargs.get("args", "")
        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "")
        cmd = self.binary_name
        if flags:
            cmd += f" {flags}"
        if args:
            cmd += f" {args}"
        if target:
            cmd += f" {target}"
        return cmd

    async def execute(self, **kwargs) -> ToolResult:
        if not self.is_available():
            return ToolResult(
                tool_name=self.name,
                command="",
                stderr=f"Tool '{self.name}' ({self.binary_name}) not installed. Install with: {self.install_command}",
                exit_code=127,
            )
        command = kwargs.get("command", "") or self.build_command(**kwargs)
        timeout = kwargs.get("timeout", self.timeout)
        return await self._run_command(command, timeout=timeout)

    def _parameters_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": f"Full command to run (e.g. '{self.binary_name} -sV target')"},
                "target": {"type": "string", "description": "Target host, IP, URL, or path"},
                "args": {"type": "string", "description": "Additional arguments"},
                "flags": {"type": "string", "description": "CLI flags"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
            },
            "required": [],
        }


class ToolRegistry:
    """Manages all available tools. Supports hot-add, auto-detection, and bulk install."""

    def __init__(self, sandbox_mode: bool = True, docker_image: str | None = None):
        self._tools: dict[str, BaseTool] = {}
        self._sandbox_mode = sandbox_mode
        self._docker_image = docker_image

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def list_tools(self, category: ToolCategory | None = None, allowed: list[str] | None = None) -> list[BaseTool]:
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        if allowed:
            tools = [t for t in tools if t.name in allowed]
        return tools

    def list_available(self) -> list[dict[str, Any]]:
        """List all tools and their availability status."""
        result = []
        for tool in self._tools.values():
            result.append({
                "name": tool.name,
                "category": tool.category.value,
                "description": tool.description,
                "available": tool.is_available(),
                "binary": tool.binary_name,
                "install": tool.install_command,
            })
        return sorted(result, key=lambda x: (x["category"], x["name"]))

    def count(self) -> int:
        return len(self._tools)

    def count_available(self) -> int:
        return sum(1 for t in self._tools.values() if t.is_available())

    def load_defaults(self) -> int:
        """Load all 200+ default tool definitions."""
        count = 0
        for name, binary, category, description, install_cmd in TOOL_DEFINITIONS:
            tool = DynamicTool(
                name=name,
                binary=binary,
                category=category,
                description=description,
                install_cmd=install_cmd,
                sandbox_mode=self._sandbox_mode,
                docker_image=self._docker_image,
            )
            self.register(tool)
            count += 1

        # Also register the generic shell tool
        self.register(ShellTool(sandbox_mode=self._sandbox_mode, docker_image=self._docker_image))
        count += 1

        logger.info("tools_loaded", total=count, available=self.count_available())
        return count

    def add_custom_tool(self, name: str, binary: str, category: str, description: str, install_cmd: str = "") -> None:
        """Add a custom tool at runtime."""
        cat = ToolCategory(category) if category in [e.value for e in ToolCategory] else ToolCategory.MISC
        tool = DynamicTool(
            name=name, binary=binary, category=cat, description=description, install_cmd=install_cmd,
            sandbox_mode=self._sandbox_mode, docker_image=self._docker_image,
        )
        self.register(tool)
        logger.info("custom_tool_added", name=name, binary=binary, available=tool.is_available())

    async def install_tool(self, name: str) -> ToolResult:
        """Try to install a tool."""
        tool = self.get(name)
        if not tool:
            return ToolResult(tool_name=name, command="", stderr=f"Tool '{name}' not in registry", exit_code=1)
        if not tool.install_command:
            return ToolResult(tool_name=name, command="", stderr="No install command defined", exit_code=1)
        shell = ShellTool(sandbox_mode=False)
        result = await shell.execute(command=tool.install_command, timeout=300)
        tool._available = None  # Reset cache
        return result

    async def install_all_available(self) -> dict[str, bool]:
        """Try to install all tools that have install commands."""
        results = {}
        for tool in self._tools.values():
            if not tool.is_available() and tool.install_command and not tool.install_command.startswith("#"):
                result = await self.install_tool(tool.name)
                results[tool.name] = result.exit_code == 0
        return results
