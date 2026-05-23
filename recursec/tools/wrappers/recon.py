"""Reconnaissance tool wrappers — subfinder, amass, theHarvester, whois, dig, shodan-cli.

Each wrapper provides structured access to external recon tools with
parsed output for agent consumption.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from recursec.core.models import ToolResult


async def _run_command(cmd: list[str], timeout: float = 300.0, stdin_data: str = "") -> tuple[str, str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        input_bytes = stdin_data.encode() if stdin_data else None
        stdout, stderr = await asyncio.wait_for(proc.communicate(input_bytes), timeout=timeout)
        return (
            stdout.decode(errors="replace") if stdout else "",
            stderr.decode(errors="replace") if stderr else "",
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return "", "Command timed out", 1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127


def _check_tool(name: str) -> bool:
    return shutil.which(name) is not None


# ── Subfinder ──────────────────────────────────────────────

class SubfinderWrapper:
    """Wrapper for subfinder — passive subdomain discovery."""

    @staticmethod
    async def enumerate(
        domain: str,
        sources: list[str] | None = None,
        max_time: int = 300,
        threads: int = 30,
        recursive: bool = False,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("subfinder"):
            return ToolResult(tool_name="subfinder", command="subfinder", stderr="subfinder not installed", exit_code=127)

        cmd = ["subfinder", "-d", domain, "-json", "-nc", "-t", str(threads)]
        if sources:
            cmd.extend(["-sources", ",".join(sources)])
        if recursive:
            cmd.append("-recursive")
        cmd.extend(["-timeout", str(max_time)])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        subdomains = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        host = data.get("host", "")
                        if host:
                            subdomains.append({"host": host, "source": data.get("source", "")})
                    except json.JSONDecodeError:
                        if "." in line:
                            subdomains.append({"host": line, "source": ""})

        return ToolResult(
            tool_name="subfinder", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"subdomains": subdomains, "total": len(subdomains)},
        )


# ── Amass ──────────────────────────────────────────────────

class AmassWrapper:
    """Wrapper for amass — in-depth attack surface mapping."""

    @staticmethod
    async def enum(
        domain: str,
        passive: bool = True,
        brute: bool = False,
        max_dns_queries: int = 0,
        timeout: float = 600.0,
    ) -> ToolResult:
        if not _check_tool("amass"):
            return ToolResult(tool_name="amass", command="amass", stderr="amass not installed", exit_code=127)

        cmd = ["amass", "enum", "-d", domain, "-json", "-"]
        if passive:
            cmd.append("-passive")
        if brute:
            cmd.append("-brute")
        if max_dns_queries > 0:
            cmd.extend(["-max-dns-queries", str(max_dns_queries)])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        subdomains = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        name = data.get("name", "")
                        if name:
                            subdomains.append({
                                "name": name,
                                "addresses": data.get("addresses", []),
                                "tag": data.get("tag", ""),
                                "sources": data.get("sources", []),
                            })
                    except json.JSONDecodeError:
                        pass

        return ToolResult(
            tool_name="amass", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"subdomains": subdomains, "total": len(subdomains)},
        )


# ── theHarvester ───────────────────────────────────────────

class TheHarvesterWrapper:
    """Wrapper for theHarvester — OSINT gathering tool."""

    @staticmethod
    async def gather(
        domain: str,
        sources: str = "anubis,baidu,bing,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,rapiddns,sublist3r,threatcrowd,urlscan,yahoo",
        limit: int = 500,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("theHarvester"):
            return ToolResult(tool_name="theHarvester", command="theHarvester", stderr="theHarvester not installed", exit_code=127)

        cmd = ["theHarvester", "-d", domain, "-b", sources, "-l", str(limit)]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        # Parse output
        emails: list[str] = []
        hosts: list[str] = []
        ips: list[str] = []
        section = ""

        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if "Emails found:" in line:
                    section = "emails"
                elif "Hosts found:" in line:
                    section = "hosts"
                elif "IPs found:" in line:
                    section = "ips"
                elif line.startswith("[*]") or line.startswith("---"):
                    continue
                elif line and section == "emails" and "@" in line:
                    emails.append(line)
                elif line and section == "hosts" and "." in line:
                    hosts.append(line)
                elif line and section == "ips":
                    ips.append(line)

        return ToolResult(
            tool_name="theHarvester", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={
                "emails": emails, "hosts": hosts, "ips": ips,
                "total_emails": len(emails), "total_hosts": len(hosts),
            },
        )


# ── Whois ──────────────────────────────────────────────────

class WhoisWrapper:
    """Wrapper for whois — domain registration lookup."""

    @staticmethod
    async def lookup(domain: str, timeout: float = 30.0) -> ToolResult:
        if not _check_tool("whois"):
            return ToolResult(tool_name="whois", command="whois", stderr="whois not installed", exit_code=127)

        cmd = ["whois", domain]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        # Parse key fields
        parsed: dict[str, Any] = {}
        if stdout:
            key_fields = [
                "Registrar:", "Creation Date:", "Updated Date:", "Registry Expiry Date:",
                "Registrant Organization:", "Registrant Country:", "Name Server:",
                "Domain Status:", "DNSSEC:", "Registrant Name:", "Registrant Email:",
                "Admin Email:", "Tech Email:",
            ]
            name_servers = []
            for line in stdout.splitlines():
                line = line.strip()
                for kf in key_fields:
                    if line.lower().startswith(kf.lower()):
                        key = kf.rstrip(":").strip().lower().replace(" ", "_")
                        val = line.split(":", 1)[1].strip() if ":" in line else ""
                        if "name_server" in key:
                            name_servers.append(val.lower())
                        else:
                            parsed[key] = val
            if name_servers:
                parsed["name_servers"] = name_servers

        return ToolResult(
            tool_name="whois", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── Dig ────────────────────────────────────────────────────

class DigWrapper:
    """Wrapper for dig — DNS query tool."""

    @staticmethod
    async def query(
        domain: str,
        record_type: str = "ANY",
        server: str = "",
        short: bool = False,
        trace: bool = False,
        timeout: float = 15.0,
    ) -> ToolResult:
        if not _check_tool("dig"):
            return ToolResult(tool_name="dig", command="dig", stderr="dig not installed", exit_code=127)

        cmd = ["dig"]
        if server:
            cmd.append(f"@{server}")
        cmd.extend([domain, record_type])
        if short:
            cmd.append("+short")
        if trace:
            cmd.append("+trace")

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        # Parse answer section
        records = []
        in_answer = False
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if ";; ANSWER SECTION:" in line:
                    in_answer = True
                    continue
                if in_answer:
                    if line.startswith(";;") or line == "":
                        in_answer = False
                        continue
                    parts = line.split()
                    if len(parts) >= 5:
                        records.append({
                            "name": parts[0],
                            "ttl": int(parts[1]) if parts[1].isdigit() else 0,
                            "class": parts[2],
                            "type": parts[3],
                            "value": " ".join(parts[4:]),
                        })

        return ToolResult(
            tool_name="dig", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"records": records, "total": len(records)},
        )

    @staticmethod
    async def zone_transfer(domain: str, nameserver: str, timeout: float = 30.0) -> ToolResult:
        cmd = ["dig", f"@{nameserver}", domain, "AXFR"]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        records = []
        if stdout and "Transfer failed" not in stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith(";"):
                    parts = line.split()
                    if len(parts) >= 5:
                        records.append({
                            "name": parts[0],
                            "ttl": int(parts[1]) if parts[1].isdigit() else 0,
                            "type": parts[3],
                            "value": " ".join(parts[4:]),
                        })

        return ToolResult(
            tool_name="dig", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={
                "zone_transfer_success": len(records) > 0,
                "records": records,
                "total": len(records),
            },
        )


# ── Nslookup ──────────────────────────────────────────────

class NslookupWrapper:
    """Wrapper for nslookup."""

    @staticmethod
    async def lookup(domain: str, server: str = "", timeout: float = 10.0) -> ToolResult:
        if not _check_tool("nslookup"):
            return ToolResult(tool_name="nslookup", command="nslookup", stderr="nslookup not installed", exit_code=127)

        cmd = ["nslookup", domain]
        if server:
            cmd.append(server)

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        return ToolResult(
            tool_name="nslookup", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
        )


# ── Whatweb ────────────────────────────────────────────────

class WhatwWebWrapper:
    """Wrapper for whatweb — web technology identification."""

    @staticmethod
    async def scan(
        url: str,
        aggression: int = 1,
        timeout: float = 60.0,
    ) -> ToolResult:
        if not _check_tool("whatweb"):
            return ToolResult(tool_name="whatweb", command="whatweb", stderr="whatweb not installed", exit_code=127)

        cmd = ["whatweb", url, f"-a{aggression}", "--log-json=-"]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        technologies = []
        if stdout:
            try:
                for line in stdout.splitlines():
                    if line.strip():
                        data = json.loads(line)
                        if isinstance(data, list) and data:
                            for entry in data:
                                plugins = entry.get("plugins", {})
                                for name, info in plugins.items():
                                    tech = {"name": name}
                                    if isinstance(info, dict):
                                        tech["version"] = info.get("version", [""])[0] if info.get("version") else ""
                                    technologies.append(tech)
                        elif isinstance(data, dict):
                            plugins = data.get("plugins", {})
                            for name in plugins:
                                technologies.append({"name": name})
            except json.JSONDecodeError:
                pass

        return ToolResult(
            tool_name="whatweb", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"technologies": technologies, "total": len(technologies)},
        )
