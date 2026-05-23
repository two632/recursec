"""Tool output parsers — extract structured data from raw tool outputs.

Each parser transforms raw CLI output into structured findings
that agents can reason about without re-parsing noisy text.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

import structlog

logger = structlog.get_logger()


def parse_tool_output(tool_name: str, raw_output: str) -> dict[str, Any]:
    """Route to the correct parser based on tool name."""
    parser = PARSERS.get(tool_name)
    if parser:
        try:
            return parser(raw_output)
        except Exception as e:
            logger.warning("parser_error", tool=tool_name, error=str(e))
    return {"raw": raw_output[:5000]}


# ── Nmap ────────────────────────────────────────────────────────

def _parse_nmap(output: str) -> dict[str, Any]:
    """Parse nmap output (both normal and XML)."""
    result: dict[str, Any] = {"hosts": [], "open_ports": [], "services": []}

    # Try XML first (nmap -oX -)
    if output.strip().startswith("<?xml") or "<nmaprun" in output:
        return _parse_nmap_xml(output)

    # Parse text output
    current_host = ""
    for line in output.split("\n"):
        line = line.strip()

        # Host discovery
        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            current_host = host_match.group(1)
            result["hosts"].append(current_host)
            continue

        # Port lines
        port_match = re.match(r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?", line)
        if port_match:
            port_info = {
                "host": current_host,
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "state": port_match.group(3),
                "service": port_match.group(4),
                "version": (port_match.group(5) or "").strip(),
            }
            if port_info["state"] == "open":
                result["open_ports"].append(port_info)
                result["services"].append(port_info)

        # OS detection
        os_match = re.match(r"OS details?: (.+)", line)
        if os_match:
            result["os_detection"] = os_match.group(1)

    result["host_count"] = len(result["hosts"])
    result["port_count"] = len(result["open_ports"])
    return result


def _parse_nmap_xml(xml_str: str) -> dict[str, Any]:
    result: dict[str, Any] = {"hosts": [], "open_ports": [], "services": []}
    try:
        root = ET.fromstring(xml_str)
        for host in root.findall(".//host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", "") if addr_el is not None else ""
            result["hosts"].append(addr)

            for port in host.findall(".//port"):
                state_el = port.find("state")
                service_el = port.find("service")
                if state_el is not None and state_el.get("state") == "open":
                    port_info = {
                        "host": addr,
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", ""),
                        "state": "open",
                        "service": service_el.get("name", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                    }
                    result["open_ports"].append(port_info)
                    result["services"].append(port_info)
    except ET.ParseError:
        pass
    result["host_count"] = len(result["hosts"])
    result["port_count"] = len(result["open_ports"])
    return result


# ── Nuclei ──────────────────────────────────────────────────────

def _parse_nuclei(output: str) -> dict[str, Any]:
    """Parse nuclei JSON output (nuclei -jsonl)."""
    findings: list[dict[str, Any]] = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Try JSON line
        try:
            data = json.loads(line)
            finding = {
                "template_id": data.get("template-id", data.get("templateID", "")),
                "name": data.get("info", {}).get("name", data.get("template-id", "")),
                "severity": data.get("info", {}).get("severity", "info"),
                "host": data.get("host", data.get("matched-at", "")),
                "matched_at": data.get("matched-at", ""),
                "description": data.get("info", {}).get("description", ""),
                "reference": data.get("info", {}).get("reference", []),
                "tags": data.get("info", {}).get("tags", []),
                "curl_command": data.get("curl-command", ""),
                "extracted_results": data.get("extracted-results", []),
            }
            sev = finding["severity"].lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            findings.append(finding)
            continue
        except json.JSONDecodeError:
            pass

        # Parse text output: [severity] [template-id] [protocol] host
        text_match = re.match(r"\[(\w+)\]\s+\[([^\]]+)\]\s+(?:\[([^\]]+)\])?\s*(.*)", line)
        if text_match:
            sev = text_match.group(1).lower()
            findings.append({
                "severity": sev,
                "template_id": text_match.group(2),
                "protocol": text_match.group(3) or "",
                "host": text_match.group(4),
            })
            if sev in severity_counts:
                severity_counts[sev] += 1

    return {"findings": findings, "severity_counts": severity_counts, "total": len(findings)}


# ── SQLMap ──────────────────────────────────────────────────────

def _parse_sqlmap(output: str) -> dict[str, Any]:
    """Parse sqlmap output."""
    result: dict[str, Any] = {
        "injectable_params": [],
        "databases": [],
        "tables": [],
        "dbms": "",
        "techniques": [],
    }

    for line in output.split("\n"):
        line = line.strip()

        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            param_match = re.search(r"parameter '(\w+)'", line)
            if param_match:
                result["injectable_params"].append(param_match.group(1))

        if "back-end DBMS" in line:
            dbms_match = re.search(r"back-end DBMS:\s*(.+)", line)
            if dbms_match:
                result["dbms"] = dbms_match.group(1).strip()

        if "available databases" in line.lower():
            pass  # Next lines will have database names

        if line.startswith("[*] "):
            db_name = line[4:].strip()
            if db_name and db_name not in result["databases"]:
                result["databases"].append(db_name)

        for technique in ["boolean-based", "time-based", "UNION", "error-based", "stacked"]:
            if technique.lower() in line.lower() and technique not in result["techniques"]:
                result["techniques"].append(technique)

    result["is_vulnerable"] = len(result["injectable_params"]) > 0
    return result


# ── Nikto ───────────────────────────────────────────────────────

def _parse_nikto(output: str) -> dict[str, Any]:
    """Parse nikto output."""
    findings = []
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("+ ") and ":" in line:
            finding = line[2:].strip()
            # Skip headers/metadata
            if any(skip in finding.lower() for skip in ["target ip:", "target hostname:", "target port:", "start time:", "end time:", "server:"]):
                continue
            findings.append(finding)

    # Extract OSVDB references
    osvdb_findings = [f for f in findings if "OSVDB" in f]

    return {
        "findings": findings,
        "osvdb_references": osvdb_findings,
        "total": len(findings),
    }


# ── Gobuster / Ffuf / Feroxbuster ──────────────────────────────

def _parse_directory_bruteforce(output: str) -> dict[str, Any]:
    """Parse directory brute-force results (gobuster, ffuf, feroxbuster)."""
    found_paths = []

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        # ffuf JSON
        try:
            data = json.loads(line)
            if "results" in data:
                for r in data["results"]:
                    found_paths.append({
                        "url": r.get("url", ""),
                        "status": r.get("status", 0),
                        "length": r.get("length", 0),
                        "words": r.get("words", 0),
                    })
                return {"paths": found_paths, "total": len(found_paths)}
        except json.JSONDecodeError:
            pass

        # Text: status code + path
        path_match = re.match(r".*?(\d{3})\s+.*?(https?://\S+|/\S+)", line)
        if path_match:
            found_paths.append({
                "status": int(path_match.group(1)),
                "path": path_match.group(2),
            })

        # Gobuster format: /path (Status: 200) [Size: 1234]
        gob_match = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)
        if gob_match:
            found_paths.append({
                "path": gob_match.group(1),
                "status": int(gob_match.group(2)),
                "size": int(gob_match.group(3)) if gob_match.group(3) else 0,
            })

    return {"paths": found_paths, "total": len(found_paths)}


# ── Semgrep ─────────────────────────────────────────────────────

def _parse_semgrep(output: str) -> dict[str, Any]:
    """Parse semgrep JSON output."""
    try:
        data = json.loads(output)
        findings = []
        for result in data.get("results", []):
            findings.append({
                "rule_id": result.get("check_id", ""),
                "path": result.get("path", ""),
                "line_start": result.get("start", {}).get("line", 0),
                "line_end": result.get("end", {}).get("line", 0),
                "message": result.get("extra", {}).get("message", ""),
                "severity": result.get("extra", {}).get("severity", ""),
                "metadata": result.get("extra", {}).get("metadata", {}),
                "fix": result.get("extra", {}).get("fix", ""),
            })
        return {
            "findings": findings,
            "total": len(findings),
            "errors": len(data.get("errors", [])),
        }
    except json.JSONDecodeError:
        # Parse text output
        findings = []
        for line in output.split("\n"):
            if ":" in line and ("error" in line.lower() or "warning" in line.lower()):
                findings.append(line.strip())
        return {"findings": findings, "total": len(findings)}


# ── Hydra / Medusa ──────────────────────────────────────────────

def _parse_credential_brute(output: str) -> dict[str, Any]:
    """Parse credential brute-force results (hydra, medusa)."""
    credentials = []
    for line in output.split("\n"):
        # Hydra: [port][service] host   login: user   password: pass
        cred_match = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
        if cred_match:
            credentials.append({
                "username": cred_match.group(1),
                "password": cred_match.group(2),
            })

        # Medusa: ACCOUNT FOUND: [service] Host: host User: user Password: pass
        med_match = re.search(r"User:\s*(\S+)\s+Password:\s*(\S+)", line)
        if med_match:
            credentials.append({
                "username": med_match.group(1),
                "password": med_match.group(2),
            })

    return {"credentials": credentials, "total": len(credentials), "success": len(credentials) > 0}


# ── Subfinder / Amass ───────────────────────────────────────────

def _parse_subdomain_enum(output: str) -> dict[str, Any]:
    """Parse subdomain enumeration results."""
    subdomains = set()
    for line in output.split("\n"):
        line = line.strip()
        if line and "." in line and not line.startswith("[") and not line.startswith("#"):
            # Basic domain validation
            if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$", line):
                subdomains.add(line.lower())
    return {"subdomains": sorted(subdomains), "total": len(subdomains)}


# ── WPScan ──────────────────────────────────────────────────────

def _parse_wpscan(output: str) -> dict[str, Any]:
    """Parse WPScan JSON output."""
    try:
        data = json.loads(output)
        vulns = []
        for vuln in data.get("interesting_findings", []) + data.get("vulnerabilities", []):
            vulns.append({
                "title": vuln.get("to_s", vuln.get("title", "")),
                "type": vuln.get("type", ""),
                "url": vuln.get("url", ""),
                "references": vuln.get("references", {}),
            })
        return {
            "version": data.get("version", {}).get("number", ""),
            "theme": data.get("main_theme", {}).get("slug", ""),
            "plugins": list(data.get("plugins", {}).keys()),
            "vulnerabilities": vulns,
            "total_vulns": len(vulns),
        }
    except json.JSONDecodeError:
        return {"raw": output[:5000]}


# ── Hashcat / John ──────────────────────────────────────────────

def _parse_hash_crack(output: str) -> dict[str, Any]:
    """Parse hash cracking results."""
    cracked = []
    for line in output.split("\n"):
        # hash:password format
        if ":" in line and not line.startswith("Session") and not line.startswith("Status"):
            parts = line.strip().split(":")
            if len(parts) >= 2:
                cracked.append({"hash": parts[0], "password": ":".join(parts[1:])})
    return {"cracked": cracked, "total": len(cracked)}


# ── Masscan ─────────────────────────────────────────────────────

def _parse_masscan(output: str) -> dict[str, Any]:
    """Parse masscan output."""
    # Try JSON first
    try:
        data = json.loads(output)
        hosts: dict[str, list[int]] = {}
        for entry in data:
            ip = entry.get("ip", "")
            for port_info in entry.get("ports", []):
                port = port_info.get("port", 0)
                if ip not in hosts:
                    hosts[ip] = []
                hosts[ip].append(port)
        return {"hosts": hosts, "host_count": len(hosts), "total_ports": sum(len(p) for p in hosts.values())}
    except (json.JSONDecodeError, TypeError):
        pass

    # Text output
    hosts_dict: dict[str, list[int]] = {}
    for line in output.split("\n"):
        match = re.match(r"Discovered open port (\d+)/(tcp|udp) on (.+)", line)
        if match:
            port = int(match.group(1))
            ip = match.group(3).strip()
            if ip not in hosts_dict:
                hosts_dict[ip] = []
            hosts_dict[ip].append(port)
    return {"hosts": hosts_dict, "host_count": len(hosts_dict), "total_ports": sum(len(p) for p in hosts_dict.values())}


# ── Trivy / Grype ───────────────────────────────────────────────

def _parse_container_scan(output: str) -> dict[str, Any]:
    """Parse container vulnerability scanner output."""
    try:
        data = json.loads(output)
        vulns = []
        # Trivy JSON format
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                vulns.append({
                    "id": vuln.get("VulnerabilityID", ""),
                    "package": vuln.get("PkgName", ""),
                    "version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "severity": vuln.get("Severity", ""),
                    "title": vuln.get("Title", ""),
                })
        return {"vulnerabilities": vulns, "total": len(vulns)}
    except json.JSONDecodeError:
        return {"raw": output[:5000]}


# ── Bandit ──────────────────────────────────────────────────────

def _parse_bandit(output: str) -> dict[str, Any]:
    """Parse bandit (Python security linter) output."""
    try:
        data = json.loads(output)
        issues = []
        for result in data.get("results", []):
            issues.append({
                "test_id": result.get("test_id", ""),
                "test_name": result.get("test_name", ""),
                "severity": result.get("issue_severity", ""),
                "confidence": result.get("issue_confidence", ""),
                "filename": result.get("filename", ""),
                "line": result.get("line_number", 0),
                "text": result.get("issue_text", ""),
                "code": result.get("code", ""),
            })
        return {"issues": issues, "total": len(issues)}
    except json.JSONDecodeError:
        return {"raw": output[:5000]}


# ── Parser Registry ─────────────────────────────────────────────

PARSERS: dict[str, Any] = {
    "nmap": _parse_nmap,
    "nuclei": _parse_nuclei,
    "sqlmap": _parse_sqlmap,
    "nikto": _parse_nikto,
    "gobuster": _parse_directory_bruteforce,
    "ffuf": _parse_directory_bruteforce,
    "feroxbuster": _parse_directory_bruteforce,
    "dirsearch": _parse_directory_bruteforce,
    "semgrep": _parse_semgrep,
    "hydra": _parse_credential_brute,
    "medusa": _parse_credential_brute,
    "ncrack": _parse_credential_brute,
    "subfinder": _parse_subdomain_enum,
    "amass": _parse_subdomain_enum,
    "wpscan": _parse_wpscan,
    "hashcat": _parse_hash_crack,
    "john": _parse_hash_crack,
    "masscan": _parse_masscan,
    "trivy": _parse_container_scan,
    "grype": _parse_container_scan,
    "bandit": _parse_bandit,
}


# ── Public Aliases ──────────────────────────────────────────────

def parse_nmap(output: str, is_xml: bool = False) -> dict[str, Any]:
    """Parse nmap output (text or XML)."""
    if is_xml:
        return _parse_nmap_xml(output)
    return _parse_nmap(output)


parse_nuclei = _parse_nuclei
parse_sqlmap = _parse_sqlmap
parse_nikto = _parse_nikto
parse_gobuster = _parse_directory_bruteforce
parse_semgrep = _parse_semgrep
parse_hydra = _parse_credential_brute
parse_subfinder = _parse_subdomain_enum
parse_amass = _parse_subdomain_enum
parse_masscan = _parse_masscan
parse_trivy = _parse_container_scan
parse_bandit = _parse_bandit
