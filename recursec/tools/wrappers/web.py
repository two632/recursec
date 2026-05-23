"""Web security tool wrappers — nuclei, nikto, sqlmap, gobuster, ffuf, wpscan, httpx.

Each wrapper converts structured parameters to CLI commands, executes with
timeout/resource control, and parses output into structured data for agents.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from typing import Any

from recursec.core.models import ToolResult
from recursec.tools.parsers import parse_nuclei, parse_nikto, parse_sqlmap, parse_gobuster


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


# ── Nuclei ─────────────────────────────────────────────────

class NucleiWrapper:
    """Wrapper for nuclei — fast vulnerability scanner."""

    @staticmethod
    async def scan(
        target: str,
        templates: list[str] | None = None,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        rate_limit: int = 150,
        concurrency: int = 25,
        timeout: float = 600.0,
        extra_args: list[str] | None = None,
    ) -> ToolResult:
        if not _check_tool("nuclei"):
            return ToolResult(tool_name="nuclei", command="nuclei", stderr="nuclei not installed", exit_code=127)

        cmd = ["nuclei", "-u", target, "-json", "-nc"]  # -nc = no color

        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        if exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
        cmd.extend(["-rate-limit", str(rate_limit)])
        cmd.extend(["-concurrency", str(concurrency)])
        if extra_args:
            cmd.extend(extra_args)

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_nuclei(stdout) if stdout else {}

        return ToolResult(
            tool_name="nuclei",
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            parsed_data=parsed,
        )

    @staticmethod
    async def scan_with_template_dir(
        target: str,
        template_dir: str,
        severity: list[str] | None = None,
        timeout: float = 600.0,
    ) -> ToolResult:
        if not _check_tool("nuclei"):
            return ToolResult(tool_name="nuclei", command="nuclei", stderr="nuclei not installed", exit_code=127)

        cmd = ["nuclei", "-u", target, "-t", template_dir, "-json", "-nc"]
        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_nuclei(stdout) if stdout else {}

        return ToolResult(
            tool_name="nuclei", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── Nikto ──────────────────────────────────────────────────

class NiktoWrapper:
    """Wrapper for nikto — web server vulnerability scanner."""

    @staticmethod
    async def scan(
        target: str,
        port: int | None = None,
        ssl: bool = False,
        tuning: str = "",
        plugins: list[str] | None = None,
        timeout: float = 600.0,
    ) -> ToolResult:
        if not _check_tool("nikto"):
            return ToolResult(tool_name="nikto", command="nikto", stderr="nikto not installed", exit_code=127)

        cmd = ["nikto", "-h", target]
        if port:
            cmd.extend(["-p", str(port)])
        if ssl:
            cmd.append("-ssl")
        if tuning:
            cmd.extend(["-Tuning", tuning])
        if plugins:
            cmd.extend(["-Plugins", ",".join(plugins)])
        cmd.extend(["-Format", "json", "-output", "-"])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_nikto(stdout) if stdout else {}

        return ToolResult(
            tool_name="nikto", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── SQLMap ─────────────────────────────────────────────────

class SqlmapWrapper:
    """Wrapper for sqlmap — automatic SQL injection tool."""

    @staticmethod
    async def scan(
        url: str,
        data: str = "",
        cookie: str = "",
        level: int = 1,
        risk: int = 1,
        technique: str = "BEUSTQ",
        dbs: bool = False,
        tables: str = "",
        dump: bool = False,
        forms: bool = False,
        batch: bool = True,
        timeout: float = 600.0,
        extra_args: list[str] | None = None,
    ) -> ToolResult:
        if not _check_tool("sqlmap"):
            return ToolResult(tool_name="sqlmap", command="sqlmap", stderr="sqlmap not installed", exit_code=127)

        cmd = ["sqlmap", "-u", url]
        if data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])
        cmd.extend(["--level", str(level)])
        cmd.extend(["--risk", str(risk)])
        cmd.extend(["--technique", technique])
        if dbs:
            cmd.append("--dbs")
        if tables:
            cmd.extend(["-D", tables, "--tables"])
        if dump:
            cmd.append("--dump")
        if forms:
            cmd.append("--forms")
        if batch:
            cmd.append("--batch")
        cmd.extend(["--output-dir", tempfile.mkdtemp(prefix="sqlmap_")])
        if extra_args:
            cmd.extend(extra_args)

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_sqlmap(stdout) if stdout else {}

        return ToolResult(
            tool_name="sqlmap", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── Gobuster ──────────────────────────────────────────────

class GobusterWrapper:
    """Wrapper for gobuster — directory/subdomain brute-forcer."""

    @staticmethod
    async def dir_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str = "",
        threads: int = 50,
        status_codes: str = "200,204,301,302,307,401,403",
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("gobuster"):
            return ToolResult(tool_name="gobuster", command="gobuster", stderr="gobuster not installed", exit_code=127)

        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", str(threads)]
        if extensions:
            cmd.extend(["-x", extensions])
        cmd.extend(["-s", status_codes, "--no-color", "-q"])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)
        parsed = parse_gobuster(stdout) if stdout else {}

        return ToolResult(
            tool_name="gobuster", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )

    @staticmethod
    async def dns_scan(
        domain: str,
        wordlist: str = "/usr/share/wordlists/dns/subdomains-top1mil-5000.txt",
        threads: int = 50,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("gobuster"):
            return ToolResult(tool_name="gobuster", command="gobuster", stderr="gobuster not installed", exit_code=127)

        cmd = ["gobuster", "dns", "-d", domain, "-w", wordlist, "-t", str(threads), "--no-color", "-q"]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        subdomains = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("="):
                    parts = line.split()
                    if parts:
                        subdomains.append(parts[0])

        return ToolResult(
            tool_name="gobuster", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"subdomains": subdomains, "total": len(subdomains)},
        )

    @staticmethod
    async def vhost_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dns/subdomains-top1mil-5000.txt",
        threads: int = 50,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("gobuster"):
            return ToolResult(tool_name="gobuster", command="gobuster", stderr="gobuster not installed", exit_code=127)

        cmd = ["gobuster", "vhost", "-u", url, "-w", wordlist, "-t", str(threads), "--no-color", "-q"]
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        return ToolResult(
            tool_name="gobuster", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
        )


# ── Ffuf ───────────────────────────────────────────────────

class FfufWrapper:
    """Wrapper for ffuf — fast web fuzzer."""

    @staticmethod
    async def fuzz(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: str = "",
        match_codes: str = "200,204,301,302,307,401,403",
        filter_size: str = "",
        filter_words: str = "",
        threads: int = 50,
        rate: int = 0,
        timeout: float = 300.0,
    ) -> ToolResult:
        if not _check_tool("ffuf"):
            return ToolResult(tool_name="ffuf", command="ffuf", stderr="ffuf not installed", exit_code=127)

        cmd = ["ffuf", "-u", url, "-w", wordlist, "-t", str(threads), "-o", "/dev/stdout", "-of", "json"]
        cmd.extend(["-X", method])
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if data:
            cmd.extend(["-d", data])
        if match_codes:
            cmd.extend(["-mc", match_codes])
        if filter_size:
            cmd.extend(["-fs", filter_size])
        if filter_words:
            cmd.extend(["-fw", filter_words])
        if rate > 0:
            cmd.extend(["-rate", str(rate)])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        parsed: dict[str, Any] = {}
        if stdout:
            try:
                data_json = json.loads(stdout)
                results = data_json.get("results", [])
                parsed = {
                    "results": [
                        {
                            "input": r.get("input", {}).get("FUZZ", ""),
                            "url": r.get("url", ""),
                            "status": r.get("status", 0),
                            "length": r.get("length", 0),
                            "words": r.get("words", 0),
                            "lines": r.get("lines", 0),
                            "redirect": r.get("redirectlocation", ""),
                        }
                        for r in results
                    ],
                    "total": len(results),
                }
            except json.JSONDecodeError:
                parsed = parse_gobuster(stdout)

        return ToolResult(
            tool_name="ffuf", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── WPScan ─────────────────────────────────────────────────

class WPScanWrapper:
    """Wrapper for wpscan — WordPress vulnerability scanner."""

    @staticmethod
    async def scan(
        url: str,
        enumerate: str = "vp,vt,cb,dbe,u",
        plugins_detection: str = "mixed",
        timeout: float = 600.0,
    ) -> ToolResult:
        if not _check_tool("wpscan"):
            return ToolResult(tool_name="wpscan", command="wpscan", stderr="wpscan not installed", exit_code=127)

        cmd = ["wpscan", "--url", url, "-e", enumerate]
        cmd.extend(["--plugins-detection", plugins_detection])
        cmd.extend(["--format", "json", "--no-banner"])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout)

        parsed: dict[str, Any] = {}
        if stdout:
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                pass

        return ToolResult(
            tool_name="wpscan", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc, parsed_data=parsed,
        )


# ── Httpx ──────────────────────────────────────────────────

class HttpxWrapper:
    """Wrapper for httpx — HTTP probing tool."""

    @staticmethod
    async def probe(
        targets: list[str],
        tech_detect: bool = True,
        status_code: bool = True,
        title: bool = True,
        web_server: bool = True,
        content_length: bool = True,
        follow_redirects: bool = True,
        threads: int = 50,
        timeout: float = 120.0,
    ) -> ToolResult:
        if not _check_tool("httpx"):
            return ToolResult(tool_name="httpx", command="httpx", stderr="httpx not installed", exit_code=127)

        cmd = ["httpx", "-json", "-nc", "-t", str(threads)]
        if tech_detect:
            cmd.append("-td")
        if status_code:
            cmd.append("-sc")
        if title:
            cmd.append("-title")
        if web_server:
            cmd.append("-server")
        if content_length:
            cmd.append("-cl")
        if follow_redirects:
            cmd.append("-fr")

        stdin_data = "\n".join(targets)
        stdout, stderr, rc = await _run_command(cmd, timeout=timeout, stdin_data=stdin_data)

        results = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        return ToolResult(
            tool_name="httpx", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
            parsed_data={"results": results, "total": len(results)},
        )


# ── Curl ───────────────────────────────────────────────────

class CurlWrapper:
    """Wrapper for curl — HTTP request tool."""

    @staticmethod
    async def request(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: str = "",
        follow_redirects: bool = True,
        insecure: bool = True,
        include_headers: bool = True,
        timeout: float = 30.0,
    ) -> ToolResult:
        if not _check_tool("curl"):
            return ToolResult(tool_name="curl", command="curl", stderr="curl not installed", exit_code=127)

        cmd = ["curl", "-s", "-X", method, url]
        if follow_redirects:
            cmd.append("-L")
        if insecure:
            cmd.append("-k")
        if include_headers:
            cmd.append("-i")
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if data:
            cmd.extend(["-d", data])
        cmd.extend(["--max-time", str(int(timeout))])

        stdout, stderr, rc = await _run_command(cmd, timeout=timeout + 5)
        return ToolResult(
            tool_name="curl", command=" ".join(cmd),
            stdout=stdout, stderr=stderr, exit_code=rc,
        )
